package cli

import (
	"fmt"

	"github.com/99designs/aws-vault/v6/prompt"
	"github.com/99designs/aws-vault/v6/vault"
	"github.com/99designs/keyring"
	"gopkg.in/alecthomas/kingpin.v2"
)

type RemoveCommandInput struct {
	ProfileName  string
	SessionsOnly bool
}

func ConfigureRemoveCommand(app *kingpin.Application, a *AwsVault) {
	input := RemoveCommandInput{}

	cmd := app.Command("remove", "Removes credentials, including sessions")
	cmd.Alias("rm")

	cmd.Arg("profile", "Name of the profile").
		Required().
		HintAction(a.MustGetProfileNames).
		StringVar(&input.ProfileName)

	cmd.Flag("sessions-only", "Only remove sessions, leave credentials intact").
		Short('s').
		BoolVar(&input.SessionsOnly)

	cmd.Action(func(c *kingpin.ParseContext) (err error) {
		keyring, err := a.Keyring()
		if err != nil {
			return err
		}
		err = RemoveCommand(input, keyring)
		app.FatalIfError(err, "remove")
		return nil
	})
}

func RemoveCommand(input RemoveCommandInput, keyring keyring.Keyring) error {
	ckr := &vault.CredentialKeyring{Keyring: keyring}
	if !input.SessionsOnly {
		r, err := prompt.TerminalPrompt(fmt.Sprintf("Delete credentials for profile %q? (Y|n) ", input.ProfileName))
		if err != nil {
			return err
		} else if r == "N" || r == "n" {
			return nil
		}

		if err := ckr.Remove(input.ProfileName); err != nil {
			return err
		}
		fmt.Printf("Deleted credentials.\n")
	}

	sk := &vault.SessionKeyring{Keyring: ckr.Keyring}
	n, err := sk.RemoveForProfile(input.ProfileName)
	if err != nil {
		return err
	}
	fmt.Printf("Deleted %d sessions.\n", n)

	return nil
}
