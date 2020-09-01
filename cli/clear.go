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

	cmd := app.Command("clear", "Clear temporary credentials from the secure keystore")

	cmd.Arg("profile", "Name of the profile").
		HintAction(a.MustGetProfileNames).
		StringVar(&input.ProfileName)

	cmd.Action(func(c *kingpin.ParseContext) (err error) {
		keyring, err := a.Keyring()
		if err != nil {
			return err
		}
		awsConfigFile, err := a.AwsConfigFile()
		if err != nil {
			return err
		}

		err = ClearCommand(input, awsConfigFile, keyring)
		app.FatalIfError(err, "clear")
		return nil
	})
}

func ClearCommand(input ClearCommandInput, awsConfigFile *vault.ConfigFile, keyring keyring.Keyring) error {
	sessions := &vault.SessionKeyring{Keyring: keyring}
	oidcTokens := &vault.OIDCTokenKeyring{Keyring: keyring}
	var oldSessionsRemoved, numSessionsRemoved, numTokensRemoved int
	var err error
	if input.ProfileName == "" {
		oldSessionsRemoved, err = sessions.RemoveOldSessions()
		if err != nil {
			return err
		}
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

		if profileSection, ok := awsConfigFile.ProfileSection(input.ProfileName); ok {
			if exists, _ := oidcTokens.Has(profileSection.SSOStartURL); exists {
				err = oidcTokens.Remove(profileSection.SSOStartURL)
				if err != nil {
					return err
				}
				numTokensRemoved = 1
			}
		}
	}
	fmt.Printf("Cleared %d sessions.\n", oldSessionsRemoved+numSessionsRemoved+numTokensRemoved)

	return nil
}
