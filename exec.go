package main

import (
	"os"
	"os/exec"
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

	env := append(os.Environ(),
		"AWS_ACCESS_KEY_ID="+val.AccessKeyID,
		"AWS_SECRET_ACCESS_KEY="+val.SecretAccessKey,
		"AWS_DEFAULT_PROFILE="+input.Profile,
	)

	if val.SessionToken != "" {
		env = append(env, "AWS_SESSION_TOKEN="+val.SessionToken)
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
