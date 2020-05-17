package cli

import (
	"fmt"

	"github.com/99designs/aws-vault/v6/vault"
	"github.com/99designs/keyring"
	"github.com/alecthomas/kingpin"
)

type ClearCacheCommandInput struct {
	ProfileName string
}

func ConfigureClearCacheCommand(app *kingpin.Application, a *AwsVault) {
	input := ClearCacheCommandInput{}

	cmd := app.Command("clear-cache", "Clear cached sessions")

	cmd.Arg("profile", "Name of the profile").
		HintAction(a.MustGetProfileNames).
		StringVar(&input.ProfileName)

	cmd.Action(func(c *kingpin.ParseContext) (err error) {
		keyring, err := a.Keyring()
		if err != nil {
			return err
		}
		err = ClearCacheCommand(input, keyring)
		app.FatalIfError(err, "clear-cache")
		return nil
	})
}

func ClearCacheCommand(input ClearCacheCommandInput, keyring keyring.Keyring) error {
	ck := &vault.CredentialKeyring{Keyring: keyring}
	sk := &vault.SessionKeyring{Keyring: ck.Keyring}
	var n int
	var err error
	if input.ProfileName == "" {
		n, err = sk.RemoveAll()
	} else {
		n, err = sk.RemoveForProfile(input.ProfileName)
	}
	if err != nil {
		return err
	}
	fmt.Printf("Deleted %d sessions.\n", n)

	return nil
}
