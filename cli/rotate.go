package cli

import (
	"fmt"

	"github.com/99designs/aws-vault/vault"
	"github.com/99designs/keyring"
	"gopkg.in/alecthomas/kingpin.v2"
)

type RotateCommandInput struct {
	ProfileName string
	Keyring     keyring.Keyring
	Config      vault.Config
}

func ConfigureRotateCommand(app *kingpin.Application) {
	input := RotateCommandInput{}

	cmd := app.Command("rotate", "Rotates credentials")

	cmd.Arg("profile", "Name of the profile").
		Required().
		HintAction(awsConfigFile.ProfileNames).
		StringVar(&input.ProfileName)

	cmd.Flag("force-new-session", "Force a new session to be created").
		Short('f').
		BoolVar(&input.Config.ForceNewSession)

	cmd.Action(func(c *kingpin.ParseContext) error {
		input.Config.MfaPromptMethod = GlobalFlags.PromptDriver
		input.Keyring = keyringImpl
		RotateCommand(app, input)
		return nil
	})
}

func RotateCommand(app *kingpin.Application, input RotateCommandInput) {

	err := configLoader.LoadFromProfile(input.ProfileName, &input.Config)
	if err != nil {
		app.Fatalf(err.Error())
		return
	}

	if input.ProfileName == input.Config.CredentialsName {
		fmt.Printf("Rotating credentials '%s' (takes 10-20 seconds)\n", input.Config.CredentialsName)
	} else {
		fmt.Printf("Rotating credentials '%s' using profile '%s' (takes 10-20 seconds)\n", input.Config.CredentialsName, input.Config.ProfileName)
	}

	if err := vault.Rotate(input.Keyring, input.Config); err != nil {
		app.Fatalf(err.Error())
		return
	}

	fmt.Println("Done!")
}
