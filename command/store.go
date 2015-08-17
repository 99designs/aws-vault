package command

import (
	"flag"
	"fmt"
	"strings"

	"github.com/99designs/aws-vault/Godeps/_workspace/src/github.com/mitchellh/cli"
	"github.com/99designs/aws-vault/keyring"
	"github.com/99designs/aws-vault/vault"
)

type storeProfileConfig interface {
	Profile(name string) (*vault.Profile, error)
}

type StoreCommand struct {
	Ui            cli.Ui
	Keyring       keyring.Keyring
	profileConfig storeProfileConfig
}

func (c *StoreCommand) Run(args []string) int {
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

	profile, err := c.profileConfig.Profile(profileName)
	if err != nil {
		c.Ui.Output(err.Error())
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

	if err = profile.Keyring(c.Keyring).Store(vault.Credentials{accessKeyId, secretKey}); err != nil {
		c.Ui.Error(err.Error())
		return 3
	}

	c.Ui.Info(fmt.Sprintf("\nAdded credentials to profile %q in vault", profileName))
	return 0
}

func storeCredentials(k keyring.Keyring, profileName, accessKeyId, secretKey string) error {
	creds := vault.Credentials{accessKeyId, secretKey}

	return keyring.Marshal(k, vault.ServiceName, profileName, &creds)
}

func (c *StoreCommand) Help() string {
	helpText := `
Usage: aws-vault store [--profile=default]
  Stores a Access Key Id and Secret Access Key to the vault via interactive prompts.
`
	return strings.TrimSpace(helpText)
}

func (c *StoreCommand) Synopsis() string {
	return "Store credentials to the vault via interactive prompts"
}
