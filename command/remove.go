package command

import (
	"flag"
	"fmt"
	"strings"

	"github.com/99designs/aws-vault/Godeps/_workspace/src/github.com/mitchellh/cli"
	"github.com/99designs/aws-vault/keyring"
	"github.com/99designs/aws-vault/vault"
)

type removeProfileConfig interface {
	Profile(name string) (*vault.Profile, error)
}

type RemoveCommand struct {
	Ui            cli.Ui
	Keyring       keyring.Keyring
	profileConfig removeProfileConfig
}

func (c *RemoveCommand) Run(args []string) int {
	var (
		profileName string
	)
	flagSet := flag.NewFlagSet("rm", flag.ExitOnError)
	flagSet.StringVar(&profileName, "profile", ProfileFromEnv(), "")
	flagSet.StringVar(&profileName, "p", ProfileFromEnv(), "")
	flagSet.Usage = func() { c.Ui.Output(c.Help()) }

	if err := flagSet.Parse(args); err != nil {
		c.Ui.Error(err.Error())
		return 1
	}

	if c.Keyring == nil {
		c.Keyring = keyring.DefaultKeyring
	}

	if c.profileConfig == nil {
		c.profileConfig = vault.DefaultProfileConfig
	}

	if _, err := c.profileConfig.Profile(profileName); err != nil {
		c.Ui.Output(err.Error())
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

	// remove session
	_, err = c.Keyring.Get(vault.SessionServiceName, profileName)
	sessionExists := (err == nil)
	if sessionExists {
		if err := c.Keyring.Remove(vault.SessionServiceName, profileName); err != nil {
			c.Ui.Error(err.Error())
			return 5
		}
	}

	c.Ui.Info(fmt.Sprintf("\nRemoved credentials and sessions for profile %q from vault", profileName))

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
