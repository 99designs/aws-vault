package main

import (
	"fmt"
	"log"

	"github.com/99designs/aws-vault/keyring"
	"github.com/99designs/aws-vault/prompt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"gopkg.in/alecthomas/kingpin.v2"
)

type RotateCommandInput struct {
	Profile   string
	Keyring   keyring.Keyring
	MfaToken  string
	MfaPrompt prompt.PromptFunc
}

func RotateCommand(app *kingpin.Application, input RotateCommandInput) {
	var err error

	conf, err := newConfigFromEnv()
	if err != nil {
		app.Fatalf("Error reading config: %v", err)
		return
	}

	profiles, err := conf.Parse()
	if err != nil {
		app.Fatalf("Error parsing config: %v", err)
		return
	}

	provider := &KeyringProvider{Keyring: input.Keyring, Profile: input.Profile}
	oldMasterCreds, err := provider.Retrieve()
	if err != nil {
		app.Fatalf(err.Error())
		return
	}

	log.Println("Found old access key")

	oldSessionCreds, err := NewVaultCredentials(input.Keyring, input.Profile, VaultOptions{
		MfaToken:  input.MfaToken,
		MfaPrompt: input.MfaPrompt,
		Profiles:  profiles,
	})
	if err != nil {
		app.Fatalf(err.Error())
		return
	}

	fmt.Println("Using old credentials to create a new access key")

	oldVal, err := oldSessionCreds.Get()
	if err != nil {
		if awsErr, ok := err.(awserr.Error); ok && awsErr.Code() == "NoCredentialProviders" {
			app.Fatalf("No credentials found for profile %q", input.Profile)
			return
		} else {
			app.Fatalf(err.Error())
			return
		}
	}

	client := iam.New(session.New(&aws.Config{
		Credentials: credentials.NewCredentials(&credentials.StaticProvider{Value: oldVal}),
	}))

	createOut, err := client.CreateAccessKey(&iam.CreateAccessKeyInput{})
	if err != nil {
		app.Fatalf(err.Error())
		return
	}

	log.Println("Created new access key")

	newMasterCreds := credentials.Value{
		AccessKeyID:     *createOut.AccessKey.AccessKeyId,
		SecretAccessKey: *createOut.AccessKey.SecretAccessKey,
	}

	if err := provider.Store(newMasterCreds); err != nil {
		app.Errorf("Can't store new access key:", newMasterCreds)
		app.Fatalf(err.Error())
		return
	}

	sessions, err := NewKeyringSessions(input.Keyring, profiles)
	if err != nil {
		app.Fatalf(err.Error())
		return
	}

	if n, _ := sessions.Delete(input.Profile); n > 0 {
		log.Printf("Deleted %d existing sessions.", n)
	}

	log.Println("Using new credentials to delete the old new access key")

	newSessionCreds, err := NewVaultCredentials(input.Keyring, input.Profile, VaultOptions{
		MfaToken:  input.MfaToken,
		MfaPrompt: input.MfaPrompt,
		Profiles:  profiles,
	})
	if err != nil {
		app.Fatalf(err.Error())
		return
	}

	newVal, err := newSessionCreds.Get()
	if err != nil {
		if awsErr, ok := err.(awserr.Error); ok && awsErr.Code() == "NoCredentialProviders" {
			app.Fatalf("No credentials found for profile %q", input.Profile)
			return
		} else {
			app.Fatalf(err.Error())
			return
		}
	}

	client = iam.New(session.New(&aws.Config{
		Credentials: credentials.NewCredentials(&credentials.StaticProvider{Value: newVal}),
	}))

	_, err = client.DeleteAccessKey(&iam.DeleteAccessKeyInput{
		AccessKeyId: aws.String(oldMasterCreds.AccessKeyID),
	})
	if err != nil {
		app.Errorf("Can't delete old access key:", oldMasterCreds)
		app.Fatalf(err.Error())
		return
	}

	log.Printf("Rotated credentials for profile %q in vault", input.Profile)
}
