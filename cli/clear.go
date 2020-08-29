package cli

import (
	"fmt"

	"github.com/99designs/aws-vault/v6/vault"
	"github.com/99designs/keyring"
	"github.com/alecthomas/kingpin"
)

type ClearCommandInput struct {
	ProfileName string
}

func ConfigureClearCommand(app *kingpin.Application, a *AwsVault) {
	input := ClearCommandInput{}

	cmd := app.Command("clear", "Clear cached short-term credentials")

	cmd.Arg("profile", "Name of the profile").
		HintAction(a.MustGetProfileNames).
		StringVar(&input.ProfileName)

	cmd.Action(func(c *kingpin.ParseContext) (err error) {
		keyring, err := a.Keyring()
		if err != nil {
			return err
		}
		err = ClearCommand(input, keyring)
		app.FatalIfError(err, "clear")
		return nil
	})
}

func ClearCommand(input ClearCommandInput, keyring keyring.Keyring) error {
	sessions := &vault.SessionKeyring{Keyring: keyring}
	oidcTokens := &vault.OIDCTokenKeyring{Keyring: keyring}
	var numSessionsRemoved, numTokensRemoved int
	var err error
	if input.ProfileName == "" {
		numSessionsRemoved, err = sessions.RemoveAll()
		if err != nil {
			return err
		}
		numTokensRemoved, err = oidcTokens.RemoveAll()
		if err != nil {
			return err
		}
	} else {
		numSessionsRemoved, err = sessions.RemoveForProfile(input.ProfileName)
		if err != nil {
			return err
		}
	}
	fmt.Printf("Cleared %d sessions.\n", numSessionsRemoved+numTokensRemoved)

	return nil
}
