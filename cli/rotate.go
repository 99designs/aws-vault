package cli

import (
	"fmt"

	"github.com/99designs/aws-vault/prompt"
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

	cmd.Flag("mfa-token", "The mfa token to use").
		Short('t').
		StringVar(&input.Config.MfaToken)

	cmd.Flag("mfa-serial", "The identification number of the MFA device to use").
		Envar("AWS_MFA_SERIAL").
		StringVar(&input.Config.MfaSerial)

	cmd.Action(func(c *kingpin.ParseContext) error {
		input.Config.MfaPrompt = prompt.Method(GlobalFlags.PromptDriver)
		input.Keyring = keyringImpl
		RotateCommand(app, input)
		return nil
	})
}

func RotateCommand(app *kingpin.Application, input RotateCommandInput) {
	err := configLoader.LoadFromProfile(input.ProfileName, &input.Config)
	if err != nil {
		app.Fatalf("%v", err)
	}

	fmt.Printf("Rotating credentials for profile %q (takes 10-20 seconds)\n", input.ProfileName)
	if err := vault.Rotate(input.ProfileName, input.Keyring, &input.Config); err != nil {
		app.Fatalf(awsConfigFile.FormatCredentialError(err, input.ProfileName))
		return
	}

	fmt.Printf("Done!\n")
}
