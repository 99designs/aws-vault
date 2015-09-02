package main

import "github.com/99designs/aws-vault/keyring"

type LsCommandInput struct {
	Keyring keyring.Keyring
}

func LsCommand(ui Ui, input LsCommandInput) {
	accounts, err := input.Keyring.List(serviceName)
	if err != nil {
		ui.Error.Fatal(err)
	}

	for _, name := range accounts {
		ui.Println(name)
	}

	if len(accounts) == 0 {
		ui.Error.Fatal("No credentials found")
	}
}
