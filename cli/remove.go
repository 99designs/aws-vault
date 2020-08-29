package cli

import (
	"fmt"

	"github.com/99designs/aws-vault/v6/prompt"
	"github.com/99designs/aws-vault/v6/vault"
	"github.com/99designs/keyring"
	"github.com/alecthomas/kingpin"
)

type RemoveCommandInput struct {
	ProfileName  string
	SessionsOnly bool
}

func ConfigureRemoveCommand(app *kingpin.Application, a *AwsVault) {
	input := RemoveCommandInput{}

	cmd := app.Command("remove", "Removes credentials from the secure keystore")
	cmd.Alias("rm")

	cmd.Arg("profile", "Name of the profile").
		Required().
		HintAction(a.MustGetProfileNames).
		StringVar(&input.ProfileName)

	cmd.Flag("sessions-only", "Only remove sessions, leave credentials intact").
		Short('s').
		Hidden().
		BoolVar(&input.SessionsOnly)

	cmd.Action(func(c *kingpin.ParseContext) error {
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

	// Legacy --sessions-only option for backwards compatibility, use aws-vault clear instead
	if input.SessionsOnly {
		sk := &vault.SessionKeyring{Keyring: ckr.Keyring}
		n, err := sk.RemoveForProfile(input.ProfileName)
		if err != nil {
			return err
		}
		fmt.Printf("Deleted %d sessions.\n", n)
		return nil
	}

	r, err := prompt.TerminalPrompt(fmt.Sprintf("Delete credentials for profile %q? (y|N) ", input.ProfileName))
	if err != nil {
		return err
	}

	if r != "Y" && r != "y" {
		return nil
	}

	if err := ckr.Remove(input.ProfileName); err != nil {
		return err
	}
	fmt.Printf("Deleted credentials.\n")

	return nil
}
