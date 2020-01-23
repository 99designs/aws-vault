package cli

import (
	"fmt"

	"github.com/99designs/keyring"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"gopkg.in/alecthomas/kingpin.v2"

	"github.com/99designs/aws-vault/vault"
)

type AddMfaDeviceCommandInput struct {
	ProfileName  string
	Keyring      keyring.Keyring
	Config       vault.Config
	Username     string
	RequireTouch bool
}

func ConfigureAddMfaCommand(app *kingpin.Application) {
	input := AddMfaDeviceCommandInput{}

	cmd := app.Command("add-mfa-device", "Adds a MFA device to the IAM user")
	cmd.Arg("username", "Name of the user to add the MFA as device for").
		Required().
		StringVar(&input.Username)

	cmd.Arg("profile", "Name of the profile").
		Required().
		HintAction(awsConfigFile.ProfileNames).
		StringVar(&input.ProfileName)

	cmd.Action(func(c *kingpin.ParseContext) error {
		input.Keyring = keyringImpl
		input.Config.MfaTokenProvider = GlobalFlags.MfaTokenProvider
		AddMFADeviceCommand(app, input)
		return nil
	})

}

func AddMFADeviceCommand(app *kingpin.Application, input AddMfaDeviceCommandInput) {
	p, found := awsConfigFile.ProfileSection(input.ProfileName)
	if !found {
		app.Fatalf("Profile with name '%s' not found")
	}

	provider := &vault.KeyringProvider{
		Keyring:         &vault.CredentialKeyring{Keyring: input.Keyring},
		CredentialsName: p.Name,
	}

	masterCreds, err := provider.Retrieve()
	if err != nil {
		app.Fatalf("unable to retrieve master creds")
	}

	sess, err := session.NewSessionWithOptions(session.Options{
		Config: aws.Config{
			Region:      aws.String(p.Region),
			Credentials: credentials.NewCredentials(&credentials.StaticProvider{Value: masterCreds}),
		},
	})
	if err != nil {
		app.Fatalf("error creating session: %s", err.Error())
	}

	tokenProvider := input.Config.GetMfaTokenProvider()

	im := vault.NewIAMMfa(sess, tokenProvider)

	fmt.Printf("Adding MFA device to user %s using profile %s\n", input.Username, p.Name)

	err = im.Add(input.Username, p.Name)
	if err != nil {
		app.Fatalf(err.Error())
	}

	fmt.Println("Done")
}
