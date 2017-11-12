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
	DefaultKeyringName = "aws-vault"
)

var (
	keyringImpl       keyring.Keyring
	awsConfig         *vault.Config
	promptsAvailable  = prompt.Available()
	backendsAvailable = keyring.SupportedBackends()
)

var GlobalFlags struct {
	Debug        bool
	Backend      string
	PromptDriver string
	KeychainName string
}

func ConfigureGlobals(app *kingpin.Application) {
	app.Flag("debug", "Show debugging output").
		BoolVar(&GlobalFlags.Debug)

	app.Flag("backend", fmt.Sprintf("Secret backend to use %v", backendsAvailable)).
		Default(keyring.DefaultBackend).
		OverrideDefaultFromEnvar("AWS_VAULT_BACKEND").
		EnumVar(&GlobalFlags.Backend, backendsAvailable...)

	app.Flag("prompt", fmt.Sprintf("Prompt driver to use %v", promptsAvailable)).
		Default("terminal").
		OverrideDefaultFromEnvar("AWS_VAULT_PROMPT").
		EnumVar(&GlobalFlags.PromptDriver, promptsAvailable...)

	app.Flag("keychain", "Name of macOS keychain to use, blank means the default keychain (usually login)").
		Default("aws-vault").
		OverrideDefaultFromEnvar("AWS_VAULT_KEYCHAIN_NAME").
		StringVar(&GlobalFlags.KeychainName)

	app.PreAction(func(c *kingpin.ParseContext) (err error) {
		if !GlobalFlags.Debug {
			log.SetOutput(ioutil.Discard)
		}
		if keyringImpl == nil {
			keychainName := DefaultKeyringName
			if GlobalFlags.Backend == keyring.KeychainBackend {
				keychainName = GlobalFlags.KeychainName
			}
			keyringImpl, err = keyring.Open(keychainName, GlobalFlags.Backend)
		}
		if awsConfig == nil {
			awsConfig, err = vault.LoadConfigFromEnv()
		}
		return err
	})

}
