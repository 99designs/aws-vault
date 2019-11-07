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
	MfaToken    string
	MfaSerial   string
	MfaPrompt   prompt.PromptFunc
}

func ConfigureRotateCommand(app *kingpin.Application) {
	input := RotateCommandInput{}

	cmd := app.Command("rotate", "Rotates credentials")
	cmd.Arg("profile", "Name of the profile").
		Required().
		HintAction(ProfileNames).
		StringVar(&input.ProfileName)

	cmd.Flag("mfa-token", "The mfa token to use").
		Short('t').
		StringVar(&input.MfaToken)

	cmd.Flag("mfa-serial", "The identification number of the MFA device to use").
		Envar("AWS_MFA_SERIAL").
		StringVar(&input.MfaSerial)

	cmd.Action(func(c *kingpin.ParseContext) error {
		input.MfaPrompt = prompt.Method(GlobalFlags.PromptDriver)
		input.Keyring = keyringImpl
		RotateCommand(app, input)
		return nil
	})
}

func RotateCommand(app *kingpin.Application, input RotateCommandInput) {
	rotator := vault.Rotator{
		Keyring:   input.Keyring,
		MfaToken:  input.MfaToken,
		MfaSerial: input.MfaSerial,
		MfaPrompt: input.MfaPrompt,
		Config:    awsConfig,
	}

	fmt.Printf("Rotating credentials for profile %q (takes 10-20 seconds)\n", input.ProfileName)

	if err := rotator.Rotate(input.ProfileName); err != nil {
		app.Fatalf(awsConfig.FormatCredentialError(err, input.ProfileName))
		return
	}

	fmt.Printf("Done!\n")
}
