package command

import (
	"encoding/json"
	"flag"
	"fmt"
	"strings"

	"github.com/99designs/aws-vault/keyring"
	"github.com/99designs/aws-vault/vault"
	"github.com/mitchellh/cli"
)

type AddCommand struct {
	Ui      cli.Ui
	Keyring keyring.Keyring
}

func (c *AddCommand) Run(args []string) int {
	cmdFlags := flag.NewFlagSet("add", flag.ContinueOnError)
	cmdFlags.Usage = func() { c.Ui.Output(c.Help()) }
	if err := cmdFlags.Parse(args); err != nil {
		return 1
	}
	cmdArgs := cmdFlags.Args()
	if len(cmdArgs) == 0 {
		c.Ui.Error("Expected the name of the key to add")
		return 1
	}

	accessKeyId, err := c.Ui.Ask("Enter Access Key ID: ")
	if err != nil {
		c.Ui.Error(err.Error())
		return 2
	}

	secretKey, err := c.Ui.AskSecret("Enter Secret Access Key: ")
	if err != nil {
		c.Ui.Error(err.Error())
		return 2
	}

	keyName := cmdArgs[0]
	plainText, err := json.Marshal(&vault.Credentials{accessKeyId, secretKey})
	if err != nil {
		c.Ui.Error(err.Error())
		return 3
	}

	if err = c.Keyring.Set(vault.ServiceName, keyName, plainText); err != nil {
		c.Ui.Error(err.Error())
		return 4
	}

	c.Ui.Info(fmt.Sprintf("\nAdded key %q to vault", keyName))
	return 0
}

func (c *AddCommand) Help() string {
	helpText := `
Usage: aws-vault add <keyname>
  Adds a Access Key Id and Secret Access Key to the vault via interactive prompts.
`
	return strings.TrimSpace(helpText)
}

func (c *AddCommand) Synopsis() string {
	return "Add credentials to the vault via interactive prompts"
}
