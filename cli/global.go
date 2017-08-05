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
	keyringImpl       keyring.Keyring
	awsConfigFile     vault.Config
	promptsAvailable  = prompt.Available()
	backendsAvailable = keyring.SupportedBackends()
)

var GlobalFlags struct {
	Debug        bool
	Backend      string
	PromptDriver string
	Biometrics   bool
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

	app.Flag("biometrics", "Use biometric authentication if supported").
		BoolVar(&GlobalFlags.Biometrics)

	app.PreAction(func(c *kingpin.ParseContext) (err error) {
		if !GlobalFlags.Debug {
			log.SetOutput(ioutil.Discard)
		}
		if keyringImpl == nil {
			keyringImpl, err = keyring.Open(KeyringName, GlobalFlags.Backend)
		}
		if globals.Biometrics {
			keyring.UseBiometricsIfAvailable = true
		}
		if awsConfigFile == nil {
			awsConfigFile, err = vault.NewConfigFromEnv()
		}
		return err
	})

}
