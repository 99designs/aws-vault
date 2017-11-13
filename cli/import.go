package cli

import (
	"fmt"

	"github.com/99designs/aws-vault/vault"
	"github.com/99designs/keyring"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"gopkg.in/alecthomas/kingpin.v2"
)

type ImportCommandInput struct {
	Profile   string
	Keyring   keyring.Keyring
	AddConfig bool
}

func ConfigureImportCommand(app *kingpin.Application) {
	input := ImportCommandInput{}

	cmd := app.Command("import", "Import all credentials from ~/.aws/credentials")
	cmd.Arg("profile", "Name of the profile").
		Required().
		StringVar(&input.Profile)

	cmd.Flag("add-config", "Add a profile to ~/.aws/config if one doesn't exist").
		Default("true").
		BoolVar(&input.AddConfig)

	cmd.Action(func(c *kingpin.ParseContext) error {
		input.Keyring = keyringImpl
		ImportCommand(app, input)
		return nil
	})
}

func ImportCommand(app *kingpin.Application, input ImportCommandInput) {
	file, err := vault.GetSharedCredentialsFile()
	if err != nil {
		app.Fatalf(err.Error())
		return
	}

	cred, err := vault.ReadCredentialsFromFile(file, input.Profile)
	if err != nil {
		app.Fatalf(err.Error())
		return
	}

	err = addCredentialsToVault(input.Profile, input.Keyring, credentials.Value{
		AccessKeyID:     cred.AccessKeyID,
		SecretAccessKey: cred.SecretAccessKey,
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

	fmt.Printf(
		"Done! You should consider rotating these credentials with `aws-vault rotate %s`\n",
		input.Profile,
	)
}
