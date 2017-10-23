package cli

import (
	"fmt"
	"log"
	"time"

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

	source, _ := awsConfig.SourceProfile(input.Profile)

	provider := &vault.KeyringProvider{
		Keyring: input.Keyring,
		Profile: source.Name,
	}

	oldMasterCreds, err := provider.Retrieve()
	if err != nil {
		app.Fatalf(err.Error())
		return
	}

	oldSess := session.New(&aws.Config{
		Credentials: credentials.NewCredentials(&credentials.StaticProvider{Value: oldMasterCreds}),
	})

	currentUserName, err := getCurrentUserName(oldSess)
	if err != nil {
		app.Fatalf(err.Error())
		return
	}

	log.Printf("Found old access key  ****************%s for user %s",
		oldMasterCreds.AccessKeyID[len(oldMasterCreds.AccessKeyID)-4:],
		currentUserName)

	// We need to use a session as some credentials will requiring assuming a role to
	// get permission to create creds
	oldSessionCreds, err := vault.NewVaultCredentials(input.Keyring, input.Profile, vault.VaultOptions{
		MfaToken:    input.MfaToken,
		MfaPrompt:   input.MfaPrompt,
		Config:      awsConfig,
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
		app.Fatalf(awsConfig.FormatCredentialError(err, input.Profile))
		return
	}

	var iamUserName *string

	// A username is needed for some IAM calls if the credentials have assumed a role
	if oldSessionVal.SessionToken != "" {
		iamUserName = aws.String(currentUserName)
	}

	oldSessionClient := iam.New(session.New(&aws.Config{
		Credentials: credentials.NewCredentials(&credentials.StaticProvider{Value: oldSessionVal}),
	}))

	createOut, err := oldSessionClient.CreateAccessKey(&iam.CreateAccessKeyInput{
		UserName: iamUserName,
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

	sessions, err := vault.NewKeyringSessions(input.Keyring, awsConfig)
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
		Config:      awsConfig,
		NoSession:   true,
		MasterCreds: &newMasterCreds,
	})
	if err != nil {
		app.Fatalf(err.Error())
		return
	}

	log.Printf("Waiting for new IAM credentials to propagate")
	time.Sleep(time.Second * 8)

	err = retry(time.Second*20, time.Second*5, func() error {
		newVal, err := newSessionCreds.Get()
		if err != nil {
			return err
		}

		newClient := iam.New(session.New(&aws.Config{
			Credentials: credentials.NewCredentials(&credentials.StaticProvider{Value: newVal}),
		}))

		_, err = newClient.DeleteAccessKey(&iam.DeleteAccessKeyInput{
			AccessKeyId: aws.String(oldMasterCreds.AccessKeyID),
			UserName:    iamUserName,
		})
		return err
	})

	if err != nil {
		app.Errorf("Can't delete old access key %v", oldMasterCreds.AccessKeyID)
		app.Fatalf(err.Error())
		return
	}

	log.Printf("Rotated credentials for profile %q in vault", input.Profile)
}

func retry(duration time.Duration, sleep time.Duration, callback func() error) (err error) {
	t0 := time.Now()
	i := 0
	for {
		i++

		err = callback()
		if err == nil {
			return
		}

		delta := time.Now().Sub(t0)
		if delta > duration {
			return fmt.Errorf("After %d attempts (during %s), last error: %s", i, delta, err)
		}

		time.Sleep(sleep)
		log.Println("Retrying after error:", err)
	}
}
