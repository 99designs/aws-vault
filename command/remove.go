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
	Ui             cli.Ui
	Keyring        keyring.Keyring
	DefaultProfile string
}

func (c *RemoveCommand) Run(args []string) int {
	var (
		profileName string
	)
	flagSet := flag.NewFlagSet("rm", flag.ExitOnError)
	flagSet.StringVar(&profileName, "profile", c.DefaultProfile, "")
	flagSet.StringVar(&profileName, "p", c.DefaultProfile, "")
	flagSet.Usage = func() { c.Ui.Output(c.Help()) }

	if err := flagSet.Parse(args); err != nil {
		c.Ui.Error(err.Error())
		return 1
	}

	r, err := c.Ui.Ask(fmt.Sprintf("Delete credentials for profile %q? (Y|n)", profileName))
	if err != nil {
		c.Ui.Error(err.Error())
		return 2
	} else if r == "N" || r == "n" {
		return 3
	}

	if err := c.Keyring.Remove(vault.ServiceName, profileName); err != nil {
		c.Ui.Error(err.Error())
		return 4
	}

	c.Ui.Info(fmt.Sprintf("\nRemoved credentials for profile %q from vault", profileName))
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
