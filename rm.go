package main

import (
	"fmt"

	"github.com/99designs/aws-vault/keyring"
	"github.com/99designs/aws-vault/prompt"
	"gopkg.in/alecthomas/kingpin.v2"
)

type RemoveCommandInput struct {
	Profile      string
	Keyring      keyring.Keyring
	SessionsOnly bool
}

func RemoveCommand(app *kingpin.Application, input RemoveCommandInput) {
	if !input.SessionsOnly {
		provider := &KeyringProvider{Keyring: input.Keyring, Profile: input.Profile}
		r, err := prompt.TerminalPrompt(fmt.Sprintf("Delete credentials for profile %q? (Y|n)", input.Profile))
		if err != nil {
			app.Fatalf(err.Error())
			return
		} else if r == "N" || r == "n" {
			return
		}

		if err := provider.Delete(); err != nil {
			app.Fatalf(err.Error())
			return
		}
		fmt.Printf("Deleted credentials.")
	}

	profiles, err := awsConfigFile.Parse()
	if err != nil {
		app.Fatalf("%v", err)
		return
	}

	sessions, err := NewKeyringSessions(input.Keyring, profiles)
	if err != nil {
		app.Fatalf(err.Error())
		return
	}

	n, err := sessions.Delete(input.Profile)
	if err != nil {
		app.Fatalf(err.Error())
		return
	}
	fmt.Printf("Deleted %d sessions.", n)
}
