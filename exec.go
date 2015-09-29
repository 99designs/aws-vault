package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/99designs/aws-vault/keyring"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
)

type ExecCommandInput struct {
	Profile  string
	Command  string
	Args     []string
	Keyring  keyring.Keyring
	Duration time.Duration
}

type envVars []string

func (e *envVars) remove(key string) {
	for i, v := range *e {
		if strings.HasPrefix(v, key+"=") {
			*e = append((*e)[:i], (*e)[i+1:]...)
		}
	}
}

func (e *envVars) add(key, val string) {
	e.remove(key)
	*e = append(*e, fmt.Sprintf("%s=%s", key, val))
}

func ExecCommand(ui Ui, input ExecCommandInput) {
	provider, err := NewVaultProvider(input.Keyring, input.Profile, input.Duration)
	if err != nil {
		ui.Error.Fatal(err)
	}

	creds := credentials.NewCredentials(provider)
	val, err := creds.Get()
	if err != nil {
		if awsErr, ok := err.(awserr.Error); ok && awsErr.Code() == "NoCredentialProviders" {
			ui.Error.Fatalf("No credentials found for profile %q", input.Profile)
		} else {
			ui.Error.Fatal(err)
		}
	}

	env := envVars(os.Environ())
	env.add("AWS_ACCESS_KEY_ID", val.AccessKeyID)
	env.add("AWS_SECRET_ACCESS_KEY", val.SecretAccessKey)
	env.add("AWS_DEFAULT_PROFILE", input.Profile)

	if val.SessionToken != "" {
		env.add("AWS_SESSION_TOKEN", val.SessionToken)
	}

	path, err := exec.LookPath(input.Command)
	if err != nil {
		ui.Error.Fatal(err)
	}

	argv := append([]string{input.Command}, input.Args...)

	if err := syscall.Exec(path, argv, env); err != nil {
		ui.Error.Fatal(err)
	}
}
