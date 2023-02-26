package cli

import (
	"fmt"
	"io"
	"log"
	"os"

	"github.com/99designs/aws-vault/v7/prompt"
	"github.com/99designs/aws-vault/v7/vault"
	"github.com/99designs/keyring"
	"github.com/alecthomas/kingpin"
	isatty "github.com/mattn/go-isatty"
	"golang.org/x/term"
)

var keyringConfigDefaults = keyring.Config{
	ServiceName:              "aws-vault",
	FilePasswordFunc:         fileKeyringPassphrasePrompt,
	LibSecretCollectionName:  "awsvault",
	KWalletAppID:             "aws-vault",
	KWalletFolder:            "aws-vault",
	KeychainTrustApplication: true,
	WinCredPrefix:            "aws-vault",
}

type AwsVault struct {
	Debug          bool
	KeyringConfig  keyring.Config
	KeyringBackend string
	promptDriver   string

	keyringImpl   keyring.Keyring
	awsConfigFile *vault.ConfigFile
}

func isATerminal() bool {
	fd := os.Stdout.Fd()
	return isatty.IsTerminal(fd) || isatty.IsCygwinTerminal(fd)
}

func (a *AwsVault) PromptDriver(avoidTerminalPrompt bool) string {
	if a.promptDriver == "" {
		a.promptDriver = "terminal"

		if !isATerminal() || avoidTerminalPrompt {
			for _, driver := range prompt.Available() {
				a.promptDriver = driver
				if driver != "terminal" {
					break
				}
			}
		}
	}

	log.Println("Using prompt driver: " + a.promptDriver)

	return a.promptDriver
}

func (a *AwsVault) Keyring() (keyring.Keyring, error) {
	if a.keyringImpl == nil {
		if a.KeyringBackend != "" {
			a.KeyringConfig.AllowedBackends = []keyring.BackendType{keyring.BackendType(a.KeyringBackend)}
		}
		var err error
		a.keyringImpl, err = keyring.Open(a.KeyringConfig)
		if err != nil {
			return nil, err
		}
	}

	return a.keyringImpl, nil
}

func (a *AwsVault) AwsConfigFile() (*vault.ConfigFile, error) {
	if a.awsConfigFile == nil {
		var err error
		a.awsConfigFile, err = vault.LoadConfigFromEnv()
		if err != nil {
			return nil, err
		}
	}

	return a.awsConfigFile, nil
}

func (a *AwsVault) MustGetProfileNames() []string {
	config, err := a.AwsConfigFile()
	if err != nil {
		log.Fatalf("Error loading AWS config: %s", err.Error())
	}
	return config.ProfileNames()
}

func ConfigureGlobals(app *kingpin.Application) *AwsVault {
	a := &AwsVault{
		KeyringConfig: keyringConfigDefaults,
	}

	backendsAvailable := []string{}
	for _, backendType := range keyring.AvailableBackends() {
		backendsAvailable = append(backendsAvailable, string(backendType))
	}

	promptsAvailable := prompt.Available()

	app.Flag("debug", "Show debugging output").
		BoolVar(&a.Debug)

	app.Flag("backend", fmt.Sprintf("Secret backend to use %v", backendsAvailable)).
		Default(backendsAvailable[0]).
		Envar("AWS_VAULT_BACKEND").
		EnumVar(&a.KeyringBackend, backendsAvailable...)

	app.Flag("prompt", fmt.Sprintf("Prompt driver to use %v", promptsAvailable)).
		Envar("AWS_VAULT_PROMPT").
		EnumVar(&a.promptDriver, promptsAvailable...)

	app.Flag("keychain", "Name of macOS keychain to use, if it doesn't exist it will be created").
		Default("aws-vault").
		Envar("AWS_VAULT_KEYCHAIN_NAME").
		StringVar(&a.KeyringConfig.KeychainName)

	app.Flag("secret-service-collection", "Name of secret-service collection to use, if it doesn't exist it will be created").
		Default("awsvault").
		Envar("AWS_VAULT_SECRET_SERVICE_COLLECTION_NAME").
		StringVar(&a.KeyringConfig.LibSecretCollectionName)

	app.Flag("pass-dir", "Pass password store directory").
		Envar("AWS_VAULT_PASS_PASSWORD_STORE_DIR").
		StringVar(&a.KeyringConfig.PassDir)

	app.Flag("pass-cmd", "Name of the pass executable").
		Envar("AWS_VAULT_PASS_CMD").
		StringVar(&a.KeyringConfig.PassCmd)

	app.Flag("pass-prefix", "Prefix to prepend to the item path stored in pass").
		Envar("AWS_VAULT_PASS_PREFIX").
		StringVar(&a.KeyringConfig.PassPrefix)

	app.Flag("file-dir", "Directory for the \"file\" password store").
		Default("~/.awsvault/keys/").
		Envar("AWS_VAULT_FILE_DIR").
		StringVar(&a.KeyringConfig.FileDir)

	app.PreAction(func(c *kingpin.ParseContext) error {
		if !a.Debug {
			log.SetOutput(io.Discard)
		}
		keyring.Debug = a.Debug
		log.Printf("aws-vault %s", app.Model().Version)
		return nil
	})

	return a
}

func fileKeyringPassphrasePrompt(prompt string) (string, error) {
	if password, ok := os.LookupEnv("AWS_VAULT_FILE_PASSPHRASE"); ok {
		return password, nil
	}

	fmt.Fprintf(os.Stderr, "%s: ", prompt)
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return "", err
	}
	fmt.Println()
	return string(b), nil
}
