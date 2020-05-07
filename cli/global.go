package cli

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/99designs/aws-vault/v6/prompt"
	"github.com/99designs/aws-vault/v6/vault"
	"github.com/99designs/keyring"
	"golang.org/x/crypto/ssh/terminal"
	kingpin "gopkg.in/alecthomas/kingpin.v2"
)

var keyringConfigDefaults = keyring.Config{
	ServiceName:              "aws-vault",
	FileDir:                  "~/.awsvault/keys/",
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
	PromptDriver   string

	keyringImpl   keyring.Keyring
	awsConfigFile *vault.ConfigFile
	configLoader  *vault.ConfigLoader
}

func (a *AwsVault) Keyring() (keyring.Keyring, error) {
	if a.keyringImpl == nil {
		a.updateKeyringConfig()
		if a.KeyringConfig.KeychainName == "" {
			a.KeyringConfig.KeychainName = "aws-vault"
		}
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

func (a *AwsVault) ConfigLoader() (*vault.ConfigLoader, error) {
	if a.configLoader == nil {
		awsConfigFile, err := a.AwsConfigFile()
		if err != nil {
			return nil, err
		}
		a.configLoader = &vault.ConfigLoader{File: awsConfigFile}
	}

	return a.configLoader, nil
}

func (a *AwsVault) updateKeyringConfig() {

	awsConfigFile, err := a.AwsConfigFile()
	if err != nil {
		log.Printf("Error loading AWS config: %s", err.Error())
		return
	}

	config, _ := awsConfigFile.DefaultProfileSection()

	// Update values from config file if not set
	if a.KeyringBackend == "" {
		a.KeyringBackend = config.AWSVaultBackend
	}
	if a.KeyringConfig.KeychainName == "" {
		a.KeyringConfig.KeychainName = config.AWSVaultKeychainName
	}
	if a.KeyringConfig.PassCmd == "" {
		a.KeyringConfig.PassCmd = config.AWSVaultPassCmd
	}
	if a.KeyringConfig.PassDir == "" {
		a.KeyringConfig.PassDir = config.AWSVaultPassDir
	}
	if a.KeyringConfig.PassPrefix == "" {
		a.KeyringConfig.PassPrefix = config.AWSVaultPassPrefix
	}
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
		Envar("AWS_VAULT_BACKEND").
		EnumVar(&a.KeyringBackend, backendsAvailable...)

	app.Flag("prompt", fmt.Sprintf("Prompt driver to use %v", promptsAvailable)).
		Envar("AWS_VAULT_PROMPT").
		EnumVar(&a.PromptDriver, promptsAvailable...)

	app.Flag("keychain", "Name of macOS keychain to use, if it doesn't exist it will be created").
		Envar("AWS_VAULT_KEYCHAIN_NAME").
		StringVar(&a.KeyringConfig.KeychainName)

	app.Flag("pass-dir", "Pass password store directory").
		Envar("AWS_VAULT_PASS_PASSWORD_STORE_DIR").
		StringVar(&a.KeyringConfig.PassDir)

	app.Flag("pass-cmd", "Name of the pass executable").
		Envar("AWS_VAULT_PASS_CMD").
		StringVar(&a.KeyringConfig.PassCmd)

	app.Flag("pass-prefix", "Prefix to prepend to the item path stored in pass").
		Envar("AWS_VAULT_PASS_PREFIX").
		StringVar(&a.KeyringConfig.PassPrefix)

	app.PreAction(func(c *kingpin.ParseContext) error {
		if !a.Debug {
			log.SetOutput(ioutil.Discard)
		}
		keyring.Debug = a.Debug
		log.Printf("aws-vault %s", app.Model().Version)
		return nil
	})

	return a
}

func fileKeyringPassphrasePrompt(prompt string) (string, error) {
	if password := os.Getenv("AWS_VAULT_FILE_PASSPHRASE"); password != "" {
		return password, nil
	}

	fmt.Fprintf(os.Stderr, "%s: ", prompt)
	b, err := terminal.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return "", err
	}
	fmt.Println()
	return string(b), nil
}
