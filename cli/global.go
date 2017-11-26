package cli

import (
	"fmt"
	"io/ioutil"
	"log"

	"github.com/99designs/aws-vault/prompt"
	"github.com/99designs/aws-vault/vault"
	"github.com/99designs/keyring"
	kingpin "gopkg.in/alecthomas/kingpin.v2"
)

const (
	KeyringName = "aws-vault"
)

var (
	keyringImpl      keyring.Keyring
	awsConfig        *vault.Config
	promptsAvailable = prompt.Available()
)

var GlobalFlags struct {
	Debug        bool
	Backend      string
	PromptDriver string
}

func ConfigureGlobals(app *kingpin.Application) {
	backendsAvailable := []string{}
	for _, backendType := range keyring.AvailableBackends() {
		backendsAvailable = append(backendsAvailable, string(backendType))
	}

	app.Flag("debug", "Show debugging output").
		BoolVar(&GlobalFlags.Debug)

	app.Flag("backend", fmt.Sprintf("Secret backend to use %v", backendsAvailable)).
		OverrideDefaultFromEnvar("AWS_VAULT_BACKEND").
		EnumVar(&GlobalFlags.Backend, backendsAvailable...)

	app.Flag("prompt", fmt.Sprintf("Prompt driver to use %v", promptsAvailable)).
		Default("terminal").
		OverrideDefaultFromEnvar("AWS_VAULT_PROMPT").
		EnumVar(&GlobalFlags.PromptDriver, promptsAvailable...)

	app.PreAction(func(c *kingpin.ParseContext) (err error) {
		if !GlobalFlags.Debug {
			log.SetOutput(ioutil.Discard)
		} else {
			keyring.Debug = true
		}
		if keyringImpl == nil {
			keyringImpl, err = keyring.Open(keyring.Config{
				ServiceName:  "aws-vault",
				KeychainName: "aws-vault",
			})
		}
		if awsConfig == nil {
			awsConfig, err = vault.LoadConfigFromEnv()
		}
		return err
	})

}
