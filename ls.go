package main

import (
	"fmt"

	"github.com/99designs/aws-vault/keyring"
	"gopkg.in/alecthomas/kingpin.v2"
)

type LsCommandInput struct {
	Keyring keyring.Keyring
}

func LsCommand(app *kingpin.Application, input LsCommandInput) {
	accounts, err := input.Keyring.Keys()
	if err != nil {
		app.Fatalf(err.Error())
		return
	}

	for _, name := range accounts {
		fmt.Println(name)
	}

	if len(accounts) == 0 {
		app.Fatalf("No credentials found")
		return
	}
}
