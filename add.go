package main

import (
	"os"

	"github.com/99designs/aws-vault/keyring"
	"github.com/aws/aws-sdk-go/aws/credentials"
)

type AddCommandInput struct {
	Profile string
	Keyring keyring.Keyring
	FromEnv bool
}

func AddCommand(ui Ui, input AddCommandInput) {
	var accessKeyId, secretKey string

	if input.FromEnv {
		if accessKeyId = os.Getenv("AWS_ACCESS_KEY_ID"); accessKeyId == "" {
			ui.Error.Fatal("Missing value for AWS_ACCESS_KEY_ID")
		}
		if secretKey = os.Getenv("AWS_SECRET_ACCESS_KEY"); secretKey == "" {
			ui.Error.Fatal("Missing value for AWS_SECRET_ACCESS_KEY")
		}
	} else {
		var err error
		if accessKeyId, err = prompt("Enter Access Key ID: "); err != nil {
			ui.Error.Fatal(err)
		}
		if secretKey, err = promptPassword("Enter Secret Access Key: "); err != nil {
			ui.Error.Fatal(err)
		}
	}

	creds := credentials.Value{AccessKeyID: accessKeyId, SecretAccessKey: secretKey}
	provider := &KeyringProvider{Keyring: input.Keyring, Profile: input.Profile}

	if err := provider.Store(creds); err != nil {
		ui.Error.Fatal(err)
	}

	ui.Printf("Added credentials to profile %q in vault", input.Profile)
}
