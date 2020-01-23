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

type RemoveMfaDeviceCommandInput struct {
	ProfileName string
	Keyring     keyring.Keyring
	Config      vault.Config
	Username    string
}

func ConfigureRemoveMfaCommand(app *kingpin.Application) {
	input := RemoveMfaDeviceCommandInput{}

	cmd := app.Command("remove-mfa-device", "Removes the MFA device associated with the IAM user")
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
		RemoveMFADeviceCommand(app, input)
		return nil
	})

}

func RemoveMFADeviceCommand(app *kingpin.Application, input RemoveMfaDeviceCommandInput) {
	p, found := awsConfigFile.ProfileSection(input.ProfileName)
	if !found {
		app.Fatalf("Profile with name '%s' not found")
	}

	provider := &vault.KeyringProvider{
		Keyring:         &vault.CredentialKeyring{Keyring: input.Keyring},
		CredentialsName: p.Name,
	}

	creds, err := provider.Retrieve()
	if err != nil {
		app.Fatalf("unable to retrieve creds for profile %s", p.Name)
	}

	sess, err := session.NewSessionWithOptions(session.Options{
		Config: aws.Config{
			Region:      aws.String(p.Region),
			Credentials: credentials.NewCredentials(&credentials.StaticProvider{Value: creds}),
		},
	})
	if err != nil {
		app.Fatalf("error creating session: %s", err.Error())
	}

	tokenProvider := input.Config.GetMfaTokenProvider()

	im := vault.NewIAMMfa(sess, tokenProvider)

	fmt.Printf("Removing MFA device for user %s using profile %s\n", input.Username, p.Name)

	err = im.Delete(input.Username)
	if err != nil {
		app.Fatalf("error removing mfa device: %s", err.Error())
	}

	fmt.Println("Done. You can safely remove the item from your mfa device")
}
