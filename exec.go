package main

import (
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/99designs/aws-vault/keyring"
	"github.com/aws/aws-sdk-go/aws/awserr"
)

type ExecCommandInput struct {
	Profile  string
	Command  string
	Args     []string
	Keyring  keyring.Keyring
	Duration time.Duration
	WriteEnv bool
	Signals  chan os.Signal
}

func ExecCommand(ui Ui, input ExecCommandInput) {
	creds, err := NewVaultCredentials(input.Keyring, input.Profile, input.Duration)
	if err != nil {
		ui.Error.Fatal(err)
	}

	val, err := creds.Get()
	if err != nil {
		if awsErr, ok := err.(awserr.Error); ok && awsErr.Code() == "NoCredentialProviders" {
			ui.Error.Fatalf("No credentials found for profile %q", input.Profile)
		} else {
			ui.Error.Fatal(err)
		}
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		ui.Error.Fatal(err)
	}

	go func() {
		log.Printf("Metadata server listening on %s", l.Addr().String())
		ui.Error.Fatal(http.Serve(l, proxyHandler(NewMetadataHandler(creds))))
	}()

	cfg, err := profileConfig(input.Profile)
	if err != nil {
		ui.Error.Fatal(cfg)
	}

	env := os.Environ()
	env = overwriteEnv(env, "http_proxy", l.Addr().String())
	env = overwriteEnv(env, "AWS_CONFIG_FILE", cfg.Name())
	env = overwriteEnv(env, "AWS_DEFAULT_PROFILE", input.Profile)

	if input.WriteEnv {
		env = overwriteEnv(env, "AWS_ACCESS_KEY_ID", val.AccessKeyID)
		env = overwriteEnv(env, "AWS_SECRET_ACCESS_KEY", val.SecretAccessKey)

		if val.SessionToken != "" {
			env = overwriteEnv(env, "AWS_SESSION_TOKEN", val.SessionToken)
		}
	}

	cmd := exec.Command(input.Command, input.Args...)
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	go func() {
		sig := <-input.Signals
		if cmd.Process != nil {
			cmd.Process.Signal(sig)
		}
	}()

	var waitStatus syscall.WaitStatus
	if err := cmd.Run(); err != nil {
		if err != nil {
			ui.Error.Println(err)
		}
		if exitError, ok := err.(*exec.ExitError); ok {
			waitStatus = exitError.Sys().(syscall.WaitStatus)
			os.Exit(waitStatus.ExitStatus())
		}
	}

}

// write out a config excluding role switching keys
func profileConfig(profile string) (*os.File, error) {
	conf, err := parseProfiles()
	if err != nil {
		return nil, err
	}

	tmpConfig, err := ioutil.TempFile(os.TempDir(), "aws-vault")
	if err != nil {
		return nil, err
	}

	// allow some time for keychain prompt
	newConfig := map[string]string{
		"metadata_service_timeout":      "15",
		"metadata_service_num_attempts": "2",
	}

	for k, v := range conf[profile] {
		if k != "source_profile" && k != "role_arn" {
			newConfig[k] = v
		}
	}

	return tmpConfig, writeProfiles(tmpConfig, profiles{profile: newConfig})
}

func overwriteEnv(env []string, key, val string) []string {
	var found bool

	for idx, e := range env {
		if strings.HasPrefix(key+"=", e) {
			env[idx] = key + "=" + val
			found = true
		} else {
			env[idx] = e
		}
	}

	if !found {
		env = append(env, key+"="+val)
	}

	return env
}

func connectProxy(w http.ResponseWriter, r *http.Request) error {
	d, err := net.Dial("tcp", r.RequestURI)
	if err != nil {
		return err
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		return err
	}
	conn, bufrw, err := hj.Hijack()
	if err != nil {
		return err
	}
	defer conn.Close()
	defer d.Close()

	bufrw.WriteString("HTTP/1.0 200 Connection established\r\n\r\n")
	bufrw.Flush()

	go io.Copy(d, conn)
	io.Copy(conn, d)

	return nil
}

func proxyHandler(upstream http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.RequestURI)
		if r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/latest/meta-data") {
			upstream.ServeHTTP(w, r)
		} else if r.Method == "CONNECT" {
			if err := connectProxy(w, r); err != nil {
				http.Error(w, "Error connecting to proxy: "+err.Error(), http.StatusGatewayTimeout)
			}
		} else {
			proxy := &httputil.ReverseProxy{Director: func(req *http.Request) {
				req.Method = "GET"
				req.URL.Scheme = "http"
				req.URL.Host = r.Host
			}}
			proxy.ServeHTTP(w, r)
		}
	})
}
