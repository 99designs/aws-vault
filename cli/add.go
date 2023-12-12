package cli

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/99designs/aws-vault/v7/prompt"
	"github.com/99designs/aws-vault/v7/vault"
	"github.com/99designs/keyring"
	"github.com/alecthomas/kingpin/v2"
	"github.com/aws/aws-sdk-go-v2/aws"
)

type AddCommandInput struct {
	ProfileName string
	FromEnv     bool
	AddConfig   bool
}

func ConfigureAddCommand(app *kingpin.Application, a *AwsVault) {
	input := AddCommandInput{}

	cmd := app.Command("add", "Add credentials to the secure keystore.")

	cmd.Arg("profile", "Name of the profile").
		Required().
		StringVar(&input.ProfileName)

	cmd.Flag("env", "Read the credentials from the environment (AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY)").
		BoolVar(&input.FromEnv)

	cmd.Flag("add-config", "Add a profile to ~/.aws/config if one doesn't exist").
		Default("true").
		BoolVar(&input.AddConfig)

	cmd.Action(func(c *kingpin.ParseContext) error {
		keyring, err := a.Keyring()
		if err != nil {
			return err
		}
		awsConfigFile, err := a.AwsConfigFile()
		if err != nil {
			return err
		}
		err = AddCommand(input, keyring, awsConfigFile)
		app.FatalIfError(err, "add")
		return nil
	})
}

func AddCommand(input AddCommandInput, keyring keyring.Keyring, awsConfigFile *vault.ConfigFile) error {
	var accessKeyId, secretKey, sessionToken, expiration string
	var expires time.Time

	p, _ := awsConfigFile.ProfileSection(input.ProfileName)
	if p.SourceProfile != "" {
		return fmt.Errorf("Your profile has a source_profile of %s, adding credentials to %s won't have any effect",
			p.SourceProfile, input.ProfileName)
	}

	if input.FromEnv {
		if accessKeyId = os.Getenv("AWS_ACCESS_KEY_ID"); accessKeyId == "" {
			return fmt.Errorf("Missing value for AWS_ACCESS_KEY_ID")
		}
		if secretKey = os.Getenv("AWS_SECRET_ACCESS_KEY"); secretKey == "" {
			return fmt.Errorf("Missing value for AWS_SECRET_ACCESS_KEY")
		}
		if sessionToken = os.Getenv("AWS_SESSION_TOKEN"); sessionToken == "" {
			return fmt.Errorf("Missing value for AWS_SESSION_TOKEN")
		}
		if expiration = os.Getenv("EXPIRATION"); expiration == "" {
			return fmt.Errorf("Missing value for EXPIRATION")
		}

		var err error
		expires, err = time.Parse(time.RFC3339, expiration)
		if err != nil {
			return fmt.Errorf("Error parsing EXPIRATION: %w", err)
		}
	} else {
		var err error
		if accessKeyId, err = prompt.TerminalPrompt("Enter Access Key ID: "); err != nil {
			return err
		}
		if secretKey, err = prompt.TerminalSecretPrompt("Enter Secret Access Key: "); err != nil {
			return err
		}
	}

	creds := aws.Credentials{AccessKeyID: accessKeyId, SecretAccessKey: secretKey, SessionToken: sessionToken, Expires: expires}

	ckr := &vault.CredentialKeyring{Keyring: keyring}
	if err := ckr.Set(input.ProfileName, creds); err != nil {
		return err
	}

	fmt.Printf("Added credentials to profile %q in vault\n", input.ProfileName)

	sk := &vault.SessionKeyring{Keyring: keyring}
	if n, _ := sk.RemoveForProfile(input.ProfileName); n > 0 {
		fmt.Printf("Deleted %d existing sessions.\n", n)
	}

	if _, hasProfile := awsConfigFile.ProfileSection(input.ProfileName); !hasProfile {
		if input.AddConfig {
			newProfileSection := vault.ProfileSection{
				Name: input.ProfileName,
			}
			log.Printf("Adding profile %s to config at %s", input.ProfileName, awsConfigFile.Path)
			if err := awsConfigFile.Add(newProfileSection); err != nil {
				return fmt.Errorf("Error adding profile: %w", err)
			}
		}
	}

	return nil
}
