package command

import (
	"flag"
	"strings"

	"github.com/99designs/aws-vault/keyring"
	"github.com/99designs/aws-vault/vault"
	"github.com/mitchellh/cli"
)

type RemoveCommand struct {
	Ui      cli.Ui
	Keyring keyring.Keyring
}

func (c *RemoveCommand) Run(args []string) int {
	cmdFlags := flag.NewFlagSet("rm", flag.ContinueOnError)
	cmdFlags.Usage = func() { c.Ui.Output(c.Help()) }
	if err := cmdFlags.Parse(args); err != nil {
		return 1
	}
	cmdArgs := cmdFlags.Args()
	if len(cmdArgs) == 0 {
		c.Ui.Error("Expected the name of the key to remove")
		return 1
	}

	if err := c.Keyring.Remove(vault.ServiceName, cmdArgs[0]); err != nil {
		c.Ui.Error(err.Error())
		return 3
	}

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
