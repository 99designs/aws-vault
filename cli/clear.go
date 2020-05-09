package cli

import (
	"gopkg.in/alecthomas/kingpin.v2"
)

func ConfigureClearCommand(app *kingpin.Application, a *AwsVault) {
	input := RemoveCommandInput{}

	cmd := app.Command("clear", "Removes sessions for the profile")

	cmd.Arg("profile", "Name of the profile").
		Required().
		HintAction(a.MustGetProfileNames).
		StringVar(&input.ProfileName)

	cmd.Action(func(c *kingpin.ParseContext) (err error) {
		keyring, err := a.Keyring()
		if err != nil {
			return err
		}
		input.SessionsOnly = true
		err = RemoveCommand(input, keyring)
		app.FatalIfError(err, "clear")
		return nil
	})
}
