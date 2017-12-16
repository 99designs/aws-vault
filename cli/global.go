package cli

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/99designs/aws-vault/prompt"
	"github.com/99designs/aws-vault/vault"
	"github.com/99designs/keyring"
	"golang.org/x/crypto/ssh/terminal"
	kingpin "gopkg.in/alecthomas/kingpin.v2"
)

const (
	DefaultKeyringName = "aws-vault"
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
	KeychainName string
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

	app.Flag("keychain", "Name of macOS keychain to use, if it doesn't exist it will be created").
		Default("aws-vault").
		OverrideDefaultFromEnvar("AWS_VAULT_KEYCHAIN_NAME").
		StringVar(&GlobalFlags.KeychainName)

	app.PreAction(func(c *kingpin.ParseContext) (err error) {
		if !GlobalFlags.Debug {
			log.SetOutput(ioutil.Discard)
		} else {
			keyring.Debug = true
		}
		if keyringImpl == nil {
			var allowedBackends []keyring.BackendType
			if GlobalFlags.Backend != "" {
				allowedBackends = append(allowedBackends, keyring.BackendType(GlobalFlags.Backend))
			}

			keyringImpl, err = keyring.Open(keyring.Config{
				ServiceName:      "aws-vault",
				AllowedBackends:  allowedBackends,
				KeychainName:     GlobalFlags.KeychainName,
				FileDir:          "~/.awsvault/keys/",
				FilePasswordFunc: fileKeyringPassphrasePrompt,
				KWalletAppID:     "aws-vault",
				KWalletFolder:    "aws-vault",
			})
		}
		if awsConfig == nil {
			awsConfig, err = vault.LoadConfigFromEnv()
		}
		return err
	})
}

func fileKeyringPassphrasePrompt(prompt string) (string, error) {
	if password := os.Getenv("AWS_VAULT_FILE_PASSPHRASE"); password != "" {
		return password, nil
	}

	fmt.Printf("%s: ", prompt)
	b, err := terminal.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return "", err
	}
	fmt.Println()
	return string(b), nil
}
