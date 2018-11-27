package cli

import (
	"fmt"

	"github.com/99designs/aws-vault/vault"
	"github.com/99designs/keyring"
	"gopkg.in/alecthomas/kingpin.v2"
)

type AddYubikeyCommandInput struct {
	Profile  string
	Keyring  keyring.Keyring
	Username string
}

func ConfigureAddYubikeyCommand(app *kingpin.Application) {
	input := AddYubikeyCommandInput{}

	cmd := app.Command("add-yubikey", "Adds a Yubikey as device")
	cmd.Arg("username", "Name of the user to add the Yubikey as device for").
		Required().
		StringVar(&input.Username)

	cmd.Arg("profile", "Name of the profile").
		Required().
		StringVar(&input.Profile)

	cmd.Action(func(c *kingpin.ParseContext) error {
		input.Keyring = keyringImpl
		AddYubikeyCommand(app, input)
		return nil
	})
}

func AddYubikeyCommand(app *kingpin.Application, input AddYubikeyCommandInput) {
	yubikey := vault.Yubikey{
		Keyring:  input.Keyring,
		Username: input.Username,
		Config:   awsConfig,
	}

	fmt.Printf("Adding yubikey to user %s using profile %s)\n", input.Username, input.Profile)

	if err := yubikey.Register(input.Profile); err != nil {
		app.Fatalf("error registering yubikey", err)
	}

	fmt.Printf("Done!\n")
}
