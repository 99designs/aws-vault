package cli

import (
	"fmt"
	"os"

	"github.com/99designs/aws-vault/prompt"
	"github.com/99designs/aws-vault/vault"
	"github.com/99designs/keyring"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"gopkg.in/alecthomas/kingpin.v2"
)

type AddCommandInput struct {
	Profile string
	Keyring keyring.Keyring
	FromEnv bool
}

func ConfigureAddCommand(app *kingpin.Application) {
	input := AddCommandInput{}

	cmd := app.Command("add", "Adds credentials, prompts if none provided")
	cmd.Arg("profile", "Name of the profile").
		Required().
		StringVar(&input.Profile)

	cmd.Flag("env", "Read the credentials from the environment").
		BoolVar(&input.FromEnv)

	cmd.Action(func(c *kingpin.ParseContext) error {
		input.Keyring = keyringImpl
		AddCommand(app, input)
		return nil
	})
}

func AddCommand(app *kingpin.Application, input AddCommandInput) {
	var accessKeyId, secretKey string

	if input.FromEnv {
		if accessKeyId = os.Getenv("AWS_ACCESS_KEY_ID"); accessKeyId == "" {
			app.Fatalf("Missing value for AWS_ACCESS_KEY_ID")
			return
		}
		if secretKey = os.Getenv("AWS_SECRET_ACCESS_KEY"); secretKey == "" {
			app.Fatalf("Missing value for AWS_SECRET_ACCESS_KEY")
			return
		}
	} else {
		var err error
		if accessKeyId, err = prompt.TerminalPrompt("Enter Access Key ID: "); err != nil {
			app.Fatalf(err.Error())
			return
		}
		if secretKey, err = prompt.TerminalPrompt("Enter Secret Access Key: "); err != nil {
			app.Fatalf(err.Error())
			return
		}
	}

	creds := credentials.Value{AccessKeyID: accessKeyId, SecretAccessKey: secretKey}
	provider := &vault.KeyringProvider{Keyring: input.Keyring, Profile: input.Profile}

	if err := provider.Store(creds); err != nil {
		app.Fatalf(err.Error())
		return
	}

	fmt.Printf("Added credentials to profile %q in vault\n", input.Profile)

	profiles, err := awsConfigFile.Parse()
	if err != nil {
		app.Fatalf("%v", err)
		return
	}

	sessions, err := vault.NewKeyringSessions(input.Keyring, profiles)
	if err != nil {
		app.Fatalf(err.Error())
		return
	}

	if n, _ := sessions.Delete(input.Profile); n > 0 {
		fmt.Printf("Deleted %d existing sessions.\n", n)
	}
}
