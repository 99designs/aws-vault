package main

import (
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/99designs/aws-vault/keyring"
	"github.com/aws/aws-sdk-go/aws/awserr"
)

type ExecCommandInput struct {
	Profile     string
	Command     string
	Args        []string
	Keyring     keyring.Keyring
	Duration    time.Duration
	MfaToken    string
	StartServer bool
	Signals     chan os.Signal
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

	env := environ(os.Environ())
	env.Set("AWS_CONFIG_FILE", cfg.Name())
	env.Set("AWS_DEFAULT_PROFILE", input.Profile)
	env.Set("AWS_PROFILE", input.Profile)

	env.Unset("AWS_ACCESS_KEY_ID")
	env.Unset("AWS_SECRET_ACCESS_KEY")
	env.Unset("AWS_CREDENTIAL_FILE")

	if region, ok := profs[input.Profile]["region"]; ok {
		env.Set("AWS_DEFAULT_REGION", region)
		env.Set("AWS_REGION", region)
	}

	writeEnv := true

	if input.StartServer {
		if err := startCredentialsServer(ui, creds); err != nil {
			ui.Error.Fatal(err)
		} else {
			writeEnv = false
		}
	}

	if writeEnv {
		ui.Debug.Println("Writing temporary credentials to ENV")

		env.Set("AWS_ACCESS_KEY_ID", val.AccessKeyID)
		env.Set("AWS_SECRET_ACCESS_KEY", val.SecretAccessKey)

		if val.SessionToken != "" {
			env.Set("AWS_SESSION_TOKEN", val.SessionToken)
			env.Set("AWS_SECURITY_TOKEN", val.SessionToken)
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

// environ is a slice of strings representing the environment, in the form "key=value".
type environ []string

// Unset an environment variable by key
func (e *environ) Unset(key string) {
	for i := range *e {
		if strings.HasPrefix((*e)[i], key+"=") {
			(*e)[i] = (*e)[len(*e)-1]
			*e = (*e)[:len(*e)-1]
			break
		}
	}
}

// Set adds an environment variable, replacing any existing ones of the same key
func (e *environ) Set(key, val string) {
	e.Unset(key)
	*e = append(*e, key+"="+val)
}
