package cli

import (
	"fmt"

	"github.com/99designs/aws-vault/prompt"
	"github.com/99designs/aws-vault/vault"
	"github.com/99designs/keyring"
	"gopkg.in/alecthomas/kingpin.v2"
)

type ExportCommandInput struct {
	Profile     string
	AllProfiles bool
	Keyring     keyring.Keyring
	MfaToken    string
	MfaPrompt   prompt.PromptFunc
}

func ConfigureExportCommand(app *kingpin.Application) {
	input := ExportCommandInput{}

	cmd := app.Command("export", "Export a profile's credentials to ~/.aws/credentials in plain text")
	cmd.Arg("profile", "Name of the profile").
		StringVar(&input.Profile)

	cmd.Flag("mfa-token", "The mfa token to use").
		Short('t').
		StringVar(&input.MfaToken)

	cmd.Flag("all", "Export all profiles").
		Short('a').
		BoolVar(&input.AllProfiles)

	cmd.Action(func(c *kingpin.ParseContext) error {
		input.MfaPrompt = prompt.Method(GlobalFlags.PromptDriver)
		input.Keyring = keyringImpl
		ExportCommand(app, input)
		return nil
	})
}

func ExportCommand(app *kingpin.Application, input ExportCommandInput) {
	if (input.Profile == "" && !input.AllProfiles) || (input.Profile != "" && input.AllProfiles) {
		app.Fatalf("Either a profile or --all must be provided")
	}

	credentials, err := input.Keyring.Keys()
	if err != nil {
		app.Fatalf(err.Error())
		return
	}

	var profiles = []string{}
	for _, profile := range credentials {
		if !vault.IsSessionKey(profile) {
			if input.AllProfiles || input.Profile == profile {
				profiles = append(profiles, profile)
			}
		}
	}

	if len(profiles) == 0 {
		app.Fatalf("No profiles found to export")
	}

	for _, profile := range profiles {
		provider := vault.KeyringProvider{
			Profile: profile,
			Keyring: input.Keyring,
		}

		val, err := provider.Retrieve()
		if err != nil {
			app.Fatalf("Failed to retrieve credentials for %q: %v", profile, err)
		}

		f, err := vault.GetSharedCredentialsFile()
		if err != nil {
			app.Fatalf("%v", err)
		}

		if err = vault.WriteCredentialsToFile(f, profile, val); err != nil {
			app.Fatalf("%v", err)
		}

		fmt.Printf("Wrote credentials for profile %q to %s\n", profile, f)
	}
}
