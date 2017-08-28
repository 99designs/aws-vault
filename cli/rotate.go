package cli

import (
	"log"

	"github.com/99designs/aws-vault/prompt"
	"github.com/99designs/aws-vault/vault"
	"github.com/99designs/keyring"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"gopkg.in/alecthomas/kingpin.v2"
)

type RotateCommandInput struct {
	Profile   string
	Keyring   keyring.Keyring
	MfaToken  string
	MfaPrompt prompt.PromptFunc
}

func ConfigureRotateCommand(app *kingpin.Application) {
	input := RotateCommandInput{}

	cmd := app.Command("rotate", "Rotates credentials")
	cmd.Arg("profile", "Name of the profile").
		Required().
		StringVar(&input.Profile)

	cmd.Flag("mfa-token", "The mfa token to use").
		Short('t').
		StringVar(&input.MfaToken)

	cmd.Action(func(c *kingpin.ParseContext) error {
		input.MfaPrompt = prompt.Method(GlobalFlags.PromptDriver)
		input.Keyring = keyringImpl
		RotateCommand(app, input)
		return nil
	})
}

func RotateCommand(app *kingpin.Application, input RotateCommandInput) {
	var err error

	profiles, err := awsConfigFile.Parse()
	if err != nil {
		app.Fatalf("Error parsing config: %v", err)
		return
	}

	provider := &vault.KeyringProvider{
		Keyring: input.Keyring,
		Profile: profiles.SourceProfile(input.Profile),
	}

	oldMasterCreds, err := provider.Retrieve()
	if err != nil {
		app.Fatalf(err.Error())
		return
	}

	oldClient := iam.New(session.New(&aws.Config{
		Credentials: credentials.NewCredentials(&credentials.StaticProvider{Value: oldMasterCreds}),
	}))

	// GetUser with a blank username returns the username for the credentials
	userOutput, err := oldClient.GetUser(&iam.GetUserInput{})
	if err != nil {
		app.Fatalf(err.Error())
		return
	}

	log.Printf("Found old access key  ****************%s for user %s",
		oldMasterCreds.AccessKeyID[len(oldMasterCreds.AccessKeyID)-4:],
		*userOutput.User.UserName)

	// We need to use a session as some credentials will requiring assuming a role to
	// get permission to create creds
	oldSessionCreds, err := vault.NewVaultCredentials(input.Keyring, input.Profile, vault.VaultOptions{
		MfaToken:    input.MfaToken,
		MfaPrompt:   input.MfaPrompt,
		Profiles:    profiles,
		NoSession:   true,
		MasterCreds: &oldMasterCreds,
	})
	if err != nil {
		app.Fatalf(err.Error())
		return
	}

	log.Println("Using old credentials to create a new access key")

	oldSessionVal, err := oldSessionCreds.Get()
	if err != nil {
		app.Fatalf(vault.FormatCredentialError(input.Profile, profiles, err))
		return
	}

	oldSessionClient := iam.New(session.New(&aws.Config{
		Credentials: credentials.NewCredentials(&credentials.StaticProvider{Value: oldSessionVal}),
	}))

	// A username is needed if the credentials are a session
	createOut, err := oldSessionClient.CreateAccessKey(&iam.CreateAccessKeyInput{
		UserName: userOutput.User.UserName,
	})
	if err != nil {
		app.Fatalf(err.Error())
		return
	}

	log.Println("Created new access key")

	newMasterCreds := credentials.Value{
		AccessKeyID:     *createOut.AccessKey.AccessKeyId,
		SecretAccessKey: *createOut.AccessKey.SecretAccessKey,
	}

	if err := provider.Store(newMasterCreds); err != nil {
		app.Errorf("Can't store new access key %v", newMasterCreds.AccessKeyID)
		app.Fatalf(err.Error())
		return
	}

	sessions, err := vault.NewKeyringSessions(input.Keyring, profiles)
	if err != nil {
		app.Fatalf(err.Error())
		return
	}

	if n, _ := sessions.Delete(input.Profile); n > 0 {
		log.Printf("Deleted %d existing sessions.", n)
	}

	log.Println("Using new credentials to delete the old new access key")

	newSessionCreds, err := vault.NewVaultCredentials(input.Keyring, input.Profile, vault.VaultOptions{
		MfaToken:    input.MfaToken,
		MfaPrompt:   input.MfaPrompt,
		Profiles:    profiles,
		NoSession:   true,
		MasterCreds: &newMasterCreds,
	})
	if err != nil {
		app.Fatalf(err.Error())
		return
	}

	newVal, err := newSessionCreds.Get()
	if err != nil {
		app.Fatalf(vault.FormatCredentialError(input.Profile, profiles, err))
		return
	}

	newClient := iam.New(session.New(&aws.Config{
		Credentials: credentials.NewCredentials(&credentials.StaticProvider{Value: newVal}),
	}))

	_, err = newClient.DeleteAccessKey(&iam.DeleteAccessKeyInput{
		AccessKeyId: aws.String(oldMasterCreds.AccessKeyID),
		UserName:    userOutput.User.UserName,
	})
	if err != nil {
		app.Errorf("Can't delete old access key %v", oldMasterCreds.AccessKeyID)
		app.Fatalf(err.Error())
		return
	}

	log.Printf("Rotated credentials for profile %q in vault", input.Profile)
}
