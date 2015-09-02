package main

import (
	"fmt"

	"github.com/99designs/aws-vault/keyring"
)

type RemoveCommandInput struct {
	Profile string
	Keyring keyring.Keyring
}

func RemoveCommand(ui Ui, input RemoveCommandInput) {
	r, err := prompt(fmt.Sprintf("Delete credentials for profile %q? (Y|n)", input.Profile))
	if err != nil {
		ui.Error.Fatal(err)
	} else if r == "N" || r == "n" {
		return
	}

	provider := &KeyringProvider{Keyring: input.Keyring, Profile: input.Profile}

	if err := provider.Delete(); err != nil {
		ui.Error.Fatal(err)
	}

	ui.Printf("Deleted credentials.")
}
