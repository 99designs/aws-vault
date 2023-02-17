package cli

import (
	"fmt"
	"strings"

	"github.com/99designs/aws-vault/v7/prompt"
	"github.com/99designs/aws-vault/v7/vault"
	"github.com/99designs/keyring"
	"github.com/alecthomas/kingpin"
)

type RemoveCommandInput struct {
	ProfileName  string
	SessionsOnly bool
	Force        bool
}

func ConfigureRemoveCommand(app *kingpin.Application, a *AwsVault) {
	input := RemoveCommandInput{}

	cmd := app.Command("remove", "Remove credentials from the secure keystore.")
	cmd.Alias("rm")

	cmd.Arg("profile", "Name of the profile").
		Required().
		HintAction(a.MustGetProfileNames).
		StringVar(&input.ProfileName)

	cmd.Flag("sessions-only", "Only remove sessions, leave credentials intact").
		Short('s').
		Hidden().
		BoolVar(&input.SessionsOnly)

	cmd.Flag("force", "Force-remove the profile without a prompt").
		Short('f').
		BoolVar(&input.Force)

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

	if !input.Force {
		r, err := prompt.TerminalPrompt(fmt.Sprintf("Delete credentials for profile %q? (y|N) ", input.ProfileName))
		if err != nil {
			return err
		}

		if !strings.EqualFold(r, "y") && !strings.EqualFold(r, "yes") {
			return nil
		}
	}

	if err := ckr.Remove(input.ProfileName); err != nil {
		return err
	}
	fmt.Printf("Deleted credentials.\n")

	return nil
}
