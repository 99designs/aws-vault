package cli

import (
	"fmt"
	"log"
	"time"

	"github.com/99designs/aws-vault/vault"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"gopkg.in/alecthomas/kingpin.v2"
)

type RotateCommandInput struct {
	NoSession   bool
	ProfileName string
	Keyring     *vault.CredentialKeyring
	Config      vault.Config
}

func ConfigureRotateCommand(app *kingpin.Application) {
	input := RotateCommandInput{}

	cmd := app.Command("rotate", "Rotates credentials")

	cmd.Flag("no-session", "Use master credentials, no session or role used").
		Short('n').
		BoolVar(&input.NoSession)

	cmd.Arg("profile", "Name of the profile").
		Required().
		HintAction(getCredentialProfileNames).
		StringVar(&input.ProfileName)

	cmd.Action(func(c *kingpin.ParseContext) error {
		input.Config.MfaPromptMethod = GlobalFlags.PromptDriver
		input.Keyring = &vault.CredentialKeyring{Keyring: keyringImpl}
		app.FatalIfError(RotateCommand(input), "rotate")
		return nil
	})
}

func RotateCommand(input RotateCommandInput) error {
	// Can't disable sessions completely, might need to use session for MFA-Protected API Access
	vault.UseSession = !input.NoSession
	vault.UseSessionCache = false

	configLoader.BaseConfig = input.Config
	configLoader.ActiveProfile = input.ProfileName
	config, err := configLoader.LoadFromProfile(input.ProfileName)
	if err != nil {
		return err
	}

	masterCredentialsName, err := vault.MasterCredentialsFor(input.ProfileName, input.Keyring, config)
	if err != nil {
		return err
	}

	if input.NoSession {
		fmt.Printf("Rotating credentials stored for profile '%s' using master credentials (takes 10-20 seconds)\n", masterCredentialsName)
	} else {
		fmt.Printf("Rotating credentials stored for profile '%s' using a session from profile '%s' (takes 10-20 seconds)\n", masterCredentialsName, input.ProfileName)
	}

	// Get the existing credentials access key ID
	oldMasterCreds, err := vault.NewMasterCredentials(input.Keyring, masterCredentialsName).Get()
	if err != nil {
		return err
	}
	oldMasterCredsAccessKeyID := vault.FormatKeyForDisplay(oldMasterCreds.AccessKeyID)
	log.Printf("Rotating access key %s\n", oldMasterCredsAccessKeyID)

	fmt.Println("Creating a new access key")

	// create a session to rotate the credentials
	var sessCreds *credentials.Credentials
	if input.NoSession {
		sessCreds = vault.NewMasterCredentials(input.Keyring, config.ProfileName)
	} else {
		sessCreds, err = vault.NewTempCredentials(config, input.Keyring)
		if err != nil {
			return fmt.Errorf("Error getting temporary credentials: %w", err)
		}
	}

	sess, err := vault.NewSession(sessCreds, config.Region)
	if err != nil {
		return err
	}

	// A username is needed for some IAM calls if the credentials have assumed a role
	iamUserName, err := getUsernameIfAssumingRole(sess, config)
	if err != nil {
		return err
	}

	// Create a new access key
	createOut, err := iam.New(sess).CreateAccessKey(&iam.CreateAccessKeyInput{
		UserName: iamUserName,
	})
	if err != nil {
		return err
	}
	fmt.Printf("Created new access key %s\n", vault.FormatKeyForDisplay(*createOut.AccessKey.AccessKeyId))

	newMasterCreds := credentials.Value{
		AccessKeyID:     *createOut.AccessKey.AccessKeyId,
		SecretAccessKey: *createOut.AccessKey.SecretAccessKey,
	}

	err = input.Keyring.Set(masterCredentialsName, newMasterCreds)
	if err != nil {
		return fmt.Errorf("Error storing new access key %s: %w", vault.FormatKeyForDisplay(newMasterCreds.AccessKeyID), err)
	}

	// Delete old sessions
	sessions := input.Keyring.Sessions()
	profileNames, err := getProfilesInChain(input.ProfileName, configLoader)
	for _, profileName := range profileNames {
		if n, _ := sessions.Delete(profileName); n > 0 {
			fmt.Printf("Deleted %d sessions for %s\n", n, profileName)
		}
	}

	// expire the cached credentials
	sessCreds.Expire()

	// Use new credentials to delete old access key
	fmt.Printf("Deleting old access key %s\n", oldMasterCredsAccessKeyID)
	err = retry(time.Second*20, time.Second*2, func() error {
		_, err = iam.New(sess).DeleteAccessKey(&iam.DeleteAccessKeyInput{
			AccessKeyId: &oldMasterCreds.AccessKeyID,
			UserName:    iamUserName,
		})
		return err
	})
	if err != nil {
		return fmt.Errorf("Can't delete old access key %s: %w", oldMasterCredsAccessKeyID, err)
	}
	fmt.Printf("Deleted old access key %s\n", oldMasterCredsAccessKeyID)

	fmt.Println("Finished rotating access key")

	return nil
}

func retry(maxTime time.Duration, sleep time.Duration, f func() error) (err error) {
	t0 := time.Now()
	i := 0
	for {
		i++

		err = f()
		if err == nil {
			return
		}

		elapsed := time.Since(t0)
		if elapsed > maxTime {
			return fmt.Errorf("After %d attempts, last error: %s", i, err)
		}

		time.Sleep(sleep)
		log.Println("Retrying after error:", err)
	}
}

func getUsernameIfAssumingRole(sess *session.Session, config *vault.Config) (*string, error) {
	if config.RoleARN != "" {
		n, err := vault.GetUsernameFromSession(sess)
		if err != nil {
			return nil, err
		}
		log.Printf("Found IAM username '%s'", n)
		return &n, nil
	}
	return nil, nil
}

func getProfilesInChain(profileName string, configLoader *vault.ConfigLoader) (profileNames []string, err error) {
	profileNames = append(profileNames, profileName)

	config, err := configLoader.LoadFromProfile(profileName)
	if err != nil {
		return profileNames, err
	}

	if config.SourceProfile != nil {
		newProfileNames, err := getProfilesInChain(config.SourceProfileName, configLoader)
		if err != nil {
			return profileNames, err
		}
		profileNames = append(profileNames, newProfileNames...)
	}

	return profileNames, nil
}
