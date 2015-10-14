package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net"
	"net/http"
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
	MfaToken string
	WriteEnv bool
	Signals  chan os.Signal
}

func ExecCommand(ui Ui, input ExecCommandInput) {
	creds, err := NewVaultCredentials(input.Keyring, input.Profile, VaultOptions{
		SessionDuration: input.Duration,
		MfaToken:        input.MfaToken,
	})
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

	profs, err := parseProfiles()
	if err != nil {
		ui.Error.Fatal(err)
	}

	cfg, err := writeTempConfig(input.Profile, profs)
	if err != nil {
		ui.Error.Fatal(err)
	}

	env := os.Environ()
	env = overwriteEnv(env, "AWS_CONFIG_FILE", cfg.Name())
	env = overwriteEnv(env, "AWS_DEFAULT_PROFILE", input.Profile)
	env = overwriteEnv(env, "AWS_PROFILE", input.Profile)

	env = unsetEnv(env, "AWS_ACCESS_KEY_ID")
	env = unsetEnv(env, "AWS_SECRET_ACCESS_KEY")
	env = unsetEnv(env, "AWS_CREDENTIAL_FILE")

	if region, ok := profs[input.Profile]["region"]; ok {
		env = overwriteEnv(env, "AWS_DEFAULT_REGION", region)
		env = overwriteEnv(env, "AWS_REGION", region)
	}

	if err := startCredentialsServer(creds); err != nil {
		ui.Debug.Println("Failed to start local credentials server", err)
		input.WriteEnv = true
	} else {
		ui.Debug.Println("Listening on local credentials server")
	}

	if input.WriteEnv {
		ui.Debug.Println("Writing temporary credentials to ENV")

		env = overwriteEnv(env, "AWS_ACCESS_KEY_ID", val.AccessKeyID)
		env = overwriteEnv(env, "AWS_SECRET_ACCESS_KEY", val.SecretAccessKey)

		if val.SessionToken != "" {
			env = overwriteEnv(env, "AWS_SESSION_TOKEN", val.SessionToken)
			env = overwriteEnv(env, "AWS_SECURITY_TOKEN", val.SessionToken)
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

func startCredentialsServer(creds *VaultCredentials) error {
	conn, err := net.DialTimeout("tcp", metadataBind, time.Millisecond*10)
	if err != nil {
		log.Printf("Unable to connect to %s, have you started the server?", metadataBind)
		return err
	}
	conn.Close()

	l, err := net.Listen("tcp", "127.0.0.1:9099")
	if err != nil {
		return err
	}

	log.Printf("Local instance role server running on %s", l.Addr())
	go http.Serve(l, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		val, err := creds.Get()
		if err != nil {
			http.Error(w, err.Error(), http.StatusGatewayTimeout)
			return
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"Code":            "Success",
			"LastUpdated":     time.Now().Format(awsTimeFormat),
			"Type":            "AWS-HMAC",
			"AccessKeyId":     val.AccessKeyID,
			"SecretAccessKey": val.SecretAccessKey,
			"Token":           val.SessionToken,
			"Expiration":      creds.Expires().Format(awsTimeFormat),
		})
	}))

	return nil
}

// write out a config excluding role switching keys
func writeTempConfig(profile string, conf profiles) (*os.File, error) {
	tmpConfig, err := ioutil.TempFile(os.TempDir(), "aws-vault")
	if err != nil {
		return nil, err
	}

	newConfig := map[string]string{}

	for k, v := range conf[profile] {
		if k != "source_profile" && k != "role_arn" {
			newConfig[k] = v
		}
	}

	return tmpConfig, writeProfiles(tmpConfig, profiles{profile: newConfig})
}

func unsetEnv(env []string, key string) []string {
	envCopy := []string{}

	for _, e := range env {
		if !strings.HasPrefix(key+"=", e) {
			envCopy = append(envCopy, e)
		}
	}

	return envCopy
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
