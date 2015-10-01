package main

import (
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
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
		ui.Error.Fatal(http.Serve(l, NewMetadataHandler(creds)))
	}()

	cfg, err := profileConfig(input.Profile)
	if err != nil {
		ui.Error.Fatal(cfg)
	}

	env := os.Environ()
	env = overwriteEnv(env, "HTTP_PROXY", l.Addr().String())
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
	cmd.Run()
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

	p := conf[profile]
	for k, _ := range p {
		switch k {
		case "source_profile", "role_arn":
			delete(p, k)
		}
	}

	// allow some time for keychain prompt
	p["metadata_service_timeout"] = "15"
	p["metadata_service_num_attempts"] = "2"

	return tmpConfig, writeProfiles(tmpConfig, profiles{profile: p})
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
