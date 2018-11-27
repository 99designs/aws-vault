package cli

import (
	"fmt"

	"github.com/99designs/aws-vault/vault"
	"github.com/99designs/keyring"
	"gopkg.in/alecthomas/kingpin.v2"
)

type RemoveYubikeyCommandInput struct {
	Profile  string
	Keyring  keyring.Keyring
	Username string
}

func ConfigureRemoveYubikeyCommand(app *kingpin.Application) {
	input := RemoveYubikeyCommandInput{}

	cmd := app.Command("remove-yubikey", "Removes Yubikey as a mfa device")
	cmd.Arg("username", "Name of the user to remove the Yubikey for").
		Required().
		StringVar(&input.Username)

	cmd.Arg("profile", "Name of the profile").
		Required().
		StringVar(&input.Profile)

	cmd.Action(func(c *kingpin.ParseContext) error {
		input.Keyring = keyringImpl
		RemoveYubikeyCommand(app, input)
		return nil
	})
}

func RemoveYubikeyCommand(app *kingpin.Application, input RemoveYubikeyCommandInput) {
	yubikey := vault.Yubikey{
		Keyring:  input.Keyring,
		Username: input.Username,
		Config:   awsConfig,
	}

	fmt.Printf("Removing yubikey for user %s using profile %s)\n", input.Username, input.Profile)

	if err := yubikey.Remove(input.Profile); err != nil {
		app.Fatalf("error removing yubikey", err)
	}

	fmt.Printf("Done!\n")
}
