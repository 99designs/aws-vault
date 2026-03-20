package cli

import (
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/alecthomas/kingpin/v2"
	"github.com/byteness/aws-vault/v7/prompt"
	"github.com/byteness/aws-vault/v7/vault"
	"github.com/byteness/keyring"
	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"
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
	OPConnectTokenEnv:        "AWS_VAULT_OP_CONNECT_TOKEN",
	OPTokenEnv:               "AWS_VAULT_OP_SERVICE_ACCOUNT_TOKEN",
	OPDesktopAccountID:       "AWS_VAULT_OP_DESKTOP_ACCOUNT_ID",
	OPTokenFunc:              keyringPassphrasePrompt,
}

type AwsVault struct {
	Debug          bool
	KeyringConfig  keyring.Config
	KeyringBackend string
	promptDriver   string
	ParallelSafe   bool

	keyringImpl   keyring.Keyring
	awsConfigFile *vault.ConfigFile
	UseBiometrics bool
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
		if a.ParallelSafe {
			lockKey := a.KeyringConfig.KeychainName
			if lockKey == "" {
				lockKey = "aws-vault"
			}
			a.keyringImpl = vault.NewLockedKeyring(a.keyringImpl, lockKey)
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
		StringVar(&a.promptDriver)

	app.Validate(func(app *kingpin.Application) error {
		if a.promptDriver == "" {
			return nil
		}
		if a.promptDriver == "pass" {
			kingpin.Fatalf("--prompt=pass (or AWS_VAULT_PROMPT=pass) has been removed from aws-vault as using TOTPs without " +
				"a dedicated device goes against security best practices. If you wish to continue using pass, " +
				"add `mfa_process = pass otp <your mfa_serial>` to profiles in your ~/.aws/config file.")
		}
		for _, v := range promptsAvailable {
			if v == a.promptDriver {
				return nil
			}
		}
		return fmt.Errorf("--prompt value must be one of %s, got '%s'", strings.Join(promptsAvailable, ","), a.promptDriver)
	})

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

	app.Flag("op-timeout", "Timeout for 1Password API operations (1Password Service Accounts only)").
		Default("15s").
		Envar("AWS_VAULT_OP_TIMEOUT").
		DurationVar(&a.KeyringConfig.OPTimeout)

	app.Flag("op-vault-id", "UUID of the 1Password vault").
		Envar("AWS_VAULT_OP_VAULT_ID").
		StringVar(&a.KeyringConfig.OPVaultID)

	app.Flag("op-item-title-prefix", "Prefix to prepend to 1Password item titles").
		Default("aws-vault").
		Envar("AWS_VAULT_OP_ITEM_TITLE_PREFIX").
		StringVar(&a.KeyringConfig.OPItemTitlePrefix)

	app.Flag("op-item-tag", "Tag to apply to 1Password items").
		Default("aws-vault").
		Envar("AWS_VAULT_OP_ITEM_TAG").
		StringVar(&a.KeyringConfig.OPItemTag)

	app.Flag("op-connect-host", "1Password Connect server HTTP(S) URI").
		Envar("AWS_VAULT_OP_CONNECT_HOST").
		StringVar(&a.KeyringConfig.OPConnectHost)

	app.Flag("op-desktop-account-id", "1Password Desktop App account name or account UUID").
		Envar("AWS_VAULT_OP_DESKTOP_ACCOUNT_ID").
		StringVar(&a.KeyringConfig.OPDesktopAccountID)

	app.Flag("biometrics", "Use biometric authentication if supported").
		Envar("AWS_VAULT_BIOMETRICS").
		BoolVar(&a.UseBiometrics)

	app.Flag("parallel-safe", "Enable cross-process locking for keychain and cached credentials").
		Envar("AWS_VAULT_PARALLEL_SAFE").
		BoolVar(&a.ParallelSafe)

	app.PreAction(func(c *kingpin.ParseContext) error {
		if !a.Debug {
			log.SetOutput(io.Discard)
		}
		keyring.Debug = a.Debug

		if a.UseBiometrics {
			configureTouchID(&a.KeyringConfig)
		}

		log.Printf("aws-vault %s", app.Model().Version)
		return nil
	})

	return a
}

func configureTouchID(k *keyring.Config) {
	k.UseBiometrics = true
	k.TouchIDAccount = "cc.byteness.aws-vault.biometrics"
	k.TouchIDService = "aws-vault"
}

func fileKeyringPassphrasePrompt(prompt string) (string, error) {
	if password, ok := os.LookupEnv("AWS_VAULT_FILE_PASSPHRASE"); ok {
		return password, nil
	}

	return keyringPassphrasePrompt(prompt)
}

func keyringPassphrasePrompt(prompt string) (string, error) {
	fmt.Fprintf(os.Stderr, "%s: ", prompt)
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return "", err
	}
	fmt.Println()
	return string(b), nil
}

// Archived library github.com/AlecAivazis/survey/v2
func pickAwsProfile(profiles []string) (string, error) {
	var ProfileName string

	// the questions to ask
	prompt := &survey.Select{
		Message: "Choose AWS profile:",
		Options: profiles,
	}
	/*var countryQs = []*survey.Question{
	      {
	          Name: "profileName",
	          Prompt: &survey.Select{
	              Message: "Choose AWS profile:",
	              Options: f.ProfileNames(),
	          },
	          Validate: survey.Required,
	      },
	  }

	  answers := struct {
	      ProfileName string
	  }{}*/

	// ask the question
	err := survey.AskOne(prompt, &ProfileName)
	//err := survey.Ask(countryQs, &answers)

	return ProfileName, err
}

// Maintained library github.com/charmbracelet/huh (TODO: needs more testing)
func pickAwsProfile2(profiles []string) (string, error) {
	var ProfileName string

	// Convert to []huh.Option
	var opts []huh.Option[string]
	for _, p := range profiles {
		opts = append(opts, huh.NewOption(p, p))
	}
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("Choose AWS profile:").
				Options(opts...).
				Value(&ProfileName))).WithHeight(9)

	err := form.Run()
	blue := lipgloss.NewStyle().Foreground(lipgloss.Color("6"))
	white := lipgloss.NewStyle().Foreground(lipgloss.Color("15"))
	fmt.Printf("%s %s\n", white.Render("Selected profile:"), blue.Render(fmt.Sprintf("%s", ProfileName)))

	return ProfileName, err
}
