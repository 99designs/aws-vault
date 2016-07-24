package main

import (
	"github.com/99designs/aws-vault/keyring"
	"github.com/99designs/aws-vault/prompt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
)

type RotateCommandInput struct {
	Profile   string
	Keyring   keyring.Keyring
	MfaToken  string
	MfaPrompt prompt.PromptFunc
}

func RotateCommand(ui Ui, input RotateCommandInput) {
	var err error

	provider := &KeyringProvider{Keyring: input.Keyring, Profile: input.Profile}

	oldMasterCreds, err := provider.Retrieve()
	if err != nil {
		ui.Error.Fatal(err)
	}

	ui.Debug.Println("Found old access key")

	oldSessionCreds, err := NewVaultCredentials(input.Keyring, input.Profile, VaultOptions{
		MfaToken:  input.MfaToken,
		MfaPrompt: input.MfaPrompt,
	})
	if err != nil {
		ui.Error.Fatal(err)
	}

	ui.Debug.Println("Using old credentials to create a new access key")

	oldVal, err := oldSessionCreds.Get()
	if err != nil {
		if awsErr, ok := err.(awserr.Error); ok && awsErr.Code() == "NoCredentialProviders" {
			ui.Error.Fatalf("No credentials found for profile %q", input.Profile)
		} else {
			ui.Error.Fatal(err)
		}
	}

	client := iam.New(session.New(&aws.Config{
		Credentials: credentials.NewCredentials(&credentials.StaticProvider{Value: oldVal}),
	}))

	createOut, err := client.CreateAccessKey(&iam.CreateAccessKeyInput{})
	if err != nil {
		ui.Error.Fatal(err)
	}

	ui.Debug.Println("Created new access key")

	newMasterCreds := credentials.Value{
		AccessKeyID:     *createOut.AccessKey.AccessKeyId,
		SecretAccessKey: *createOut.AccessKey.SecretAccessKey,
	}

	if err := provider.Store(newMasterCreds); err != nil {
		ui.Error.Println("Can't store new access key:", newMasterCreds)
		ui.Error.Fatal(err)
	}

	sessions, err := NewKeyringSessions(input.Keyring)
	if err != nil {
		ui.Error.Fatal(err)
	}

	if n, _ := sessions.Delete(input.Profile); n > 0 {
		ui.Debug.Printf("Deleted %d existing sessions.", n)
	}

	ui.Debug.Println("Using new credentials to delete the old new access key")

	newSessionCreds, err := NewVaultCredentials(input.Keyring, input.Profile, VaultOptions{
		MfaToken:  input.MfaToken,
		MfaPrompt: input.MfaPrompt,
	})
	if err != nil {
		ui.Error.Fatal(err)
	}

	newVal, err := newSessionCreds.Get()
	if err != nil {
		if awsErr, ok := err.(awserr.Error); ok && awsErr.Code() == "NoCredentialProviders" {
			ui.Error.Fatalf("No credentials found for profile %q", input.Profile)
		} else {
			ui.Error.Fatal(err)
		}
	}

	client = iam.New(session.New(&aws.Config{
		Credentials: credentials.NewCredentials(&credentials.StaticProvider{Value: newVal}),
	}))

	_, err = client.DeleteAccessKey(&iam.DeleteAccessKeyInput{
		AccessKeyId: aws.String(oldMasterCreds.AccessKeyID),
	})
	if err != nil {
		ui.Error.Println("Can't delete old access key:", oldMasterCreds)
		ui.Error.Fatal(err)
	}

	ui.Printf("Rotated credentials for profile %q in vault", input.Profile)
	ui.Exit(0)
}
