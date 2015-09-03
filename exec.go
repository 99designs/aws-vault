package main

import (
	"os"
	"os/exec"

	"github.com/99designs/aws-vault/keyring"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
)

type ExecCommandInput struct {
	Profile string
	Command string
	Args    []string
	Keyring keyring.Keyring
}

func ExecCommand(ui Ui, input ExecCommandInput) {
	provider, err := NewVaultProvider(input.Keyring, input.Profile)
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
	)

	if val.SessionToken != "" {
		env = append(env, "AWS_SESSION_TOKEN="+val.SessionToken)
	}

	cmd := exec.Command(input.Command, input.Args...)
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = &logWriter{ui.Logger}
	cmd.Stderr = &logWriter{ui.Error}

	if err := cmd.Run(); err != nil {
		ui.Error.Fatal(err)
	}
}
