package command

import (
	"flag"
	"fmt"
	"strings"

	"github.com/99designs/aws-vault/Godeps/_workspace/src/github.com/mitchellh/cli"
	"github.com/99designs/aws-vault/keyring"
	"github.com/99designs/aws-vault/vault"
)

type RemoveCommand struct {
	Ui      cli.Ui
	Keyring keyring.Keyring
}

func (c *RemoveCommand) Run(args []string) int {
	config, err := parseFlags(args, func(f *flag.FlagSet) {
		f.Usage = func() { c.Ui.Output(c.Help()) }
	})

	r, err := c.Ui.Ask(fmt.Sprintf("Delete credentials for profile %q? (Y|n)", config.Profile))
	if err != nil {
		c.Ui.Error(err.Error())
		return 2
	} else if r == "N" || r == "n" {
		return 3
	}

	if err := c.Keyring.Remove(vault.ServiceName, config.Profile); err != nil {
		c.Ui.Error(err.Error())
		return 4
	}

	c.Ui.Info(fmt.Sprintf("\nRemoved credentials for profile %q from vault", config.Profile))
	return 0
}

func (c *RemoveCommand) Help() string {
	helpText := `
Usage: aws-vault rm <keyname>
  Removes credentials from vault
`
	return strings.TrimSpace(helpText)
}

func (c *RemoveCommand) Synopsis() string {
	return "Remove credentials from vault"
}
