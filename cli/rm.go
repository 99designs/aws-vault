package cli

import (
	"fmt"

	"github.com/99designs/aws-vault/prompt"
	"github.com/99designs/aws-vault/vault"
	"github.com/99designs/keyring"
	"gopkg.in/alecthomas/kingpin.v2"
)

type RemoveCommandInput struct {
	ProfileName  string
	Keyring      keyring.Keyring
	SessionsOnly bool
}

func ConfigureRemoveCommand(app *kingpin.Application) {
	input := RemoveCommandInput{}

	cmd := app.Command("remove", "Removes credentials, including sessions")
	cmd.Alias("rm")

	cmd.Arg("profile", "Name of the profile").
		Required().
		StringVar(&input.ProfileName)

	cmd.Flag("sessions-only", "Only remove sessions, leave credentials intact").
		Short('s').
		BoolVar(&input.SessionsOnly)

	cmd.Action(func(c *kingpin.ParseContext) error {
		input.Keyring = keyringImpl
		RemoveCommand(app, input)
		return nil
	})
}

func RemoveCommand(app *kingpin.Application, input RemoveCommandInput) {
	if !input.SessionsOnly {
		provider := &vault.KeyringProvider{Keyring: input.Keyring, Profile: input.ProfileName}
		r, err := prompt.TerminalPrompt(fmt.Sprintf("Delete credentials for profile %q? (Y|n)", input.ProfileName))
		if err != nil {
			app.Fatalf(err.Error())
			return
		} else if r == "N" || r == "n" {
			return
		}

		if err := provider.Delete(); err != nil {
			app.Fatalf(err.Error())
			return
		}
		fmt.Printf("Deleted credentials.\n")
	}

	sessions, err := vault.NewKeyringSessions(input.Keyring, awsConfig)
	if err != nil {
		app.Fatalf(err.Error())
		return
	}

	n, err := sessions.Delete(input.ProfileName)
	if err != nil {
		app.Fatalf(err.Error())
		return
	}
	fmt.Printf("Deleted %d sessions.\n", n)
}
