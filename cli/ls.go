package cli

import (
	"fmt"

	"github.com/99designs/keyring"
	"gopkg.in/alecthomas/kingpin.v2"
)

type LsCommandInput struct {
	Keyring keyring.Keyring
}

func ConfigureListCommand(app *kingpin.Application) {
	input := LsCommandInput{}

	cmd := app.Command("list", "List profiles, along with their credentials and sessions")
	cmd.Alias("ls")
	cmd.Action(func(c *kingpin.ParseContext) error {
		input.Keyring = keyringImpl
		LsCommand(app, input)
		return nil
	})
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
