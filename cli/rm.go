package cli

import (
	"fmt"

	"github.com/99designs/aws-vault/prompt"
	"github.com/99designs/aws-vault/vault"
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
		ckr, err := a.NewCredentialKeyring()
		if err != nil {
			return err
		}
		err = RemoveCommand(input, ckr)
		app.FatalIfError(err, "remove")
		return nil
	})
}

func RemoveCommand(input RemoveCommandInput, ckr *vault.CredentialKeyring) error {
	if !input.SessionsOnly {
		r, err := prompt.TerminalPrompt(fmt.Sprintf("Delete credentials for profile %q? (Y|n)", input.ProfileName))
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

	sessions := ckr.Sessions()

	n, err := sessions.Delete(input.ProfileName)
	if err != nil {
		return err
	}
	fmt.Printf("Deleted %d sessions.\n", n)

	return nil
}
