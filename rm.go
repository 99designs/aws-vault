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
	provider := &KeyringProvider{Keyring: input.Keyring, Profile: input.Profile}
	r, err := prompt(fmt.Sprintf("Delete credentials for profile %q? (Y|n)", input.Profile))
	if err != nil {
		ui.Error.Fatal(err)
	} else if r == "N" || r == "n" {
		return
	}

	if err := provider.Delete(); err != nil {
		ui.Error.Fatal(err)
	}
	ui.Printf("Deleted credentials.")

	sessions, err := NewKeyringSessions(input.Keyring)
	if err != nil {
		ui.Error.Fatal(err)
	}

	n, err := sessions.Delete(input.Profile)
	if err != nil {
		ui.Error.Fatal(err)
	}
	ui.Printf("Deleted %d sessions.", n)
}
