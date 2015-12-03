package main

import (
	"fmt"

	"github.com/99designs/aws-vault/keyring"
	"github.com/99designs/aws-vault/prompt"
)

type RemoveCommandInput struct {
	Profile      string
	Keyring      keyring.Keyring
	SessionsOnly bool
}

func RemoveCommand(ui Ui, input RemoveCommandInput) {
	if !input.SessionsOnly {
		provider := &KeyringProvider{Keyring: input.Keyring, Profile: input.Profile}
		r, err := prompt.TerminalPrompt(fmt.Sprintf("Delete credentials for profile %q? (Y|n)", input.Profile))
		if err != nil {
			ui.Error.Fatal(err)
		} else if r == "N" || r == "n" {
			return
		}

		if err := provider.Delete(); err != nil {
			ui.Error.Fatal(err)
		}
		ui.Printf("Deleted credentials.")
	}

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
