package main

import (
	"github.com/99designs/aws-vault/keyring"
)

type LogoutCommandInput struct {
	Profile string
	Keyring keyring.Keyring
}

func LogoutCommand(ui Ui, input LogoutCommandInput) {
	provider := &KeyringProvider{Keyring: input.Keyring, Profile: input.Profile}
	if err := provider.DeleteSession(); err != nil {
		ui.Error.Fatal(err)
	}
	ui.Printf("Deleted session for %s.", input.Profile)
}
