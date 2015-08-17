package command

import (
	"strings"

	"github.com/99designs/aws-vault/Godeps/_workspace/src/github.com/mitchellh/cli"
	"github.com/99designs/aws-vault/keyring"
	"github.com/99designs/aws-vault/vault"
)

type ListCommand struct {
	Ui      cli.Ui
	Keyring keyring.Keyring
}

func (c *ListCommand) Run(args []string) int {
	if c.Keyring == nil {
		c.Keyring = keyring.DefaultKeyring
	}

	profileNames, err := c.Keyring.List(vault.ServiceName)
	if err != nil {
		c.Ui.Error(err.Error())
		return 4
	}
	for _, p := range profileNames {
		c.Ui.Output(p)
	}
	return 0
}

func (c *ListCommand) Help() string {
	helpText := `
Usage: aws-vault ls
  Lists profiles with credentials in the vault
`
	return strings.TrimSpace(helpText)
}

func (c *ListCommand) Synopsis() string {
	return "Lists profiles with credentials in the vault"
}
