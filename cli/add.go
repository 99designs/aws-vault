package cli

import (
	"fmt"
	"log"
	"os"

	"github.com/99designs/aws-vault/prompt"
	"github.com/99designs/aws-vault/vault"
	"github.com/99designs/keyring"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"gopkg.in/alecthomas/kingpin.v2"
)

type AddCommandInput struct {
	Profile   string
	Keyring   keyring.Keyring
	FromEnv   bool
	AddConfig bool
}

func ConfigureAddCommand(app *kingpin.Application) {
	input := AddCommandInput{}

	cmd := app.Command("add", "Adds credentials, prompts if none provided")
	cmd.Arg("profile", "Name of the profile").
		Required().
		StringVar(&input.Profile)

	cmd.Flag("env", "Read the credentials from the environment").
		BoolVar(&input.FromEnv)

	cmd.Flag("add-config", "Add a profile to ~/.aws/config if one doesn't exist").
		Default("true").
		BoolVar(&input.AddConfig)

	cmd.Action(func(c *kingpin.ParseContext) error {
		input.Keyring = keyringImpl
		AddCommand(app, input)
		return nil
	})
}

func AddCommand(app *kingpin.Application, input AddCommandInput) {
	var accessKeyId, secretKey string

	if input.FromEnv {
		if accessKeyId = os.Getenv("AWS_ACCESS_KEY_ID"); accessKeyId == "" {
			app.Fatalf("Missing value for AWS_ACCESS_KEY_ID")
			return
		}
		if secretKey = os.Getenv("AWS_SECRET_ACCESS_KEY"); secretKey == "" {
			app.Fatalf("Missing value for AWS_SECRET_ACCESS_KEY")
			return
		}
	} else {
		var err error
		if accessKeyId, err = prompt.TerminalPrompt("Enter Access Key ID: "); err != nil {
			app.Fatalf(err.Error())
			return
		}
		if secretKey, err = prompt.TerminalPrompt("Enter Secret Access Key: "); err != nil {
			app.Fatalf(err.Error())
			return
		}
	}
	err := addCredentialsToVault(input.Profile, input.Keyring, credentials.Value{
		AccessKeyID:     accessKeyId,
		SecretAccessKey: secretKey,
	})
	if err != nil {
		app.Fatalf(err.Error())
		return
	}

	if input.AddConfig {
		if err = addProfileToConfig(input.Profile); err != nil {
			app.Fatalf(err.Error())
			return
		}
	}
}

func addCredentialsToVault(profile string, kr keyring.Keyring, creds credentials.Value) error {
	if source, _ := awsConfig.SourceProfile(profile); source.Name != profile {
		return fmt.Errorf(
			"Your profile has a source_profile of %s, adding credentials to %s won't have any effect",
			source.Name, profile,
		)
	}

	provider := &vault.KeyringProvider{
		Keyring: kr,
		Profile: profile,
	}

	fmt.Printf("Added credentials to profile %q in vault\n", profile)
	if err := provider.Store(creds); err != nil {
		return err
	}

	sessions, err := vault.NewKeyringSessions(kr, awsConfig)
	if err != nil {
		return err
	}

	if n, _ := sessions.Delete(profile); n > 0 {
		fmt.Printf("Deleted %d existing sessions.\n", n)
	}

	return nil
}

func addProfileToConfig(profile string) error {
	if _, hasProfile := awsConfig.Profile(profile); !hasProfile {
		// copy a source profile if one exists
		newProfileFromSource, _ := awsConfig.SourceProfile(profile)
		newProfileFromSource.Name = profile

		log.Printf("Adding profile %s to config at %s", profile, awsConfig.Path)
		if err := awsConfig.Add(newProfileFromSource); err != nil {
			return fmt.Errorf("Error adding profile: %#v", err)
		}
	}

	return nil
}
