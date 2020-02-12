package cli

import (
	"fmt"

	"github.com/99designs/keyring"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"gopkg.in/alecthomas/kingpin.v2"

	"github.com/99designs/aws-vault/vault"
)

type ListMfaDevicesCommandInput struct {
	ProfileName  string
	Keyring      keyring.Keyring
	Config       vault.Config
	Username     string
	RequireTouch bool
}

func ConfigureListMfaDevicesCommand(app *kingpin.Application) {
	input := ListMfaDevicesCommandInput{}

	cmd := app.Command("list-mfa-devices", "Lists the MFA devices for the IAM user")
	cmd.Arg("username", "Name of the user to list the MFA devices for").
		Required().
		StringVar(&input.Username)

	cmd.Arg("profile", "Name of the profile to use").
		HintAction(awsConfigFile.ProfileNames).
		StringVar(&input.ProfileName)

	cmd.Action(func(c *kingpin.ParseContext) error {
		input.Keyring = keyringImpl
		input.Config.MfaTokenProvider = GlobalFlags.MfaTokenProvider
		ListMFADevicesCommand(app, input)
		return nil
	})

}

func ListMFADevicesCommand(app *kingpin.Application, input ListMfaDevicesCommandInput) {
	var sess *session.Session
	var err error
	if input.ProfileName != "" {
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

		sess, err = session.NewSessionWithOptions(session.Options{
			Config: aws.Config{
				Region:      aws.String(p.Region),
				Credentials: credentials.NewCredentials(&credentials.StaticProvider{Value: creds}),
			},
		})
	} else {
		sess, err = session.NewSession(&aws.Config{})

	}
	if err != nil {
		app.Fatalf("error creating session: %s", err.Error())
	}

	svc := iam.New(sess)

	result, err := svc.ListMFADevices(&iam.ListMFADevicesInput{
		UserName: aws.String(input.Username),
	})
	if err != nil {
		app.Fatalf("failed to list mfa devices: %s", err.Error())
	}

	fmt.Println(result.MFADevices)
}
