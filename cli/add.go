package cli

import (
	"fmt"
	"log"
	"os"

	"github.com/99designs/aws-vault/v5/prompt"
	"github.com/99designs/aws-vault/v5/vault"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"gopkg.in/alecthomas/kingpin.v2"
)

type AddCommandInput struct {
	ProfileName string
	FromEnv     bool
	AddConfig   bool
}

func ConfigureAddCommand(app *kingpin.Application, a *AwsVault) {
	input := AddCommandInput{}

	cmd := app.Command("add", "Adds credentials, prompts if none provided")

	cmd.Arg("profile", "Name of the profile").
		Required().
		StringVar(&input.ProfileName)

	cmd.Flag("env", "Read the credentials from the environment").
		BoolVar(&input.FromEnv)

	cmd.Flag("add-config", "Add a profile to ~/.aws/config if one doesn't exist").
		Default("true").
		BoolVar(&input.AddConfig)

	cmd.Action(func(c *kingpin.ParseContext) error {
		kr, err := a.NewCredentialKeyring()
		if err != nil {
			return err
		}
		awsConfigFile, err := a.AwsConfigFile()
		if err != nil {
			return err
		}
		err = AddCommand(input, kr, awsConfigFile)
		app.FatalIfError(err, "add")
		return nil
	})
}

func AddCommand(input AddCommandInput, keyring *vault.CredentialKeyring, awsConfigFile *vault.ConfigFile) error {
	var accessKeyId, secretKey string

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
	} else {
		var err error
		if accessKeyId, err = prompt.TerminalPrompt("Enter Access Key ID: "); err != nil {
			return fmt.Errorf(err.Error())
		}
		if secretKey, err = prompt.TerminalPrompt("Enter Secret Access Key: "); err != nil {
			return fmt.Errorf(err.Error())
		}
	}

	creds := credentials.Value{AccessKeyID: accessKeyId, SecretAccessKey: secretKey}

	if err := keyring.Set(input.ProfileName, creds); err != nil {
		return err
	}

	fmt.Printf("Added credentials to profile %q in vault\n", input.ProfileName)

	sessions := keyring.Sessions()

	if n, _ := sessions.Delete(input.ProfileName); n > 0 {
		fmt.Printf("Deleted %d existing sessions.\n", n)
	}

	if _, hasProfile := awsConfigFile.ProfileSection(input.ProfileName); !hasProfile {
		if input.AddConfig {
			newProfileSection := vault.ProfileSection{
				Name: input.ProfileName,
			}
			log.Printf("Adding profile %s to config at %s", input.ProfileName, awsConfigFile.Path)
			if err := awsConfigFile.Add(newProfileSection); err != nil {
				return fmt.Errorf("Error adding profile: %#v", err)
			}
		}
	}

	return nil
}
