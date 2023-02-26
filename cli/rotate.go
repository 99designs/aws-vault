package cli

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/99designs/aws-vault/v7/vault"
	"github.com/99designs/keyring"
	"github.com/alecthomas/kingpin"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

type RotateCommandInput struct {
	NoSession   bool
	ProfileName string
	Config      vault.Config
}

func ConfigureRotateCommand(app *kingpin.Application, a *AwsVault) {
	input := RotateCommandInput{}

	cmd := app.Command("rotate", "Rotate credentials.")

	cmd.Flag("no-session", "Use master credentials, no session or role used").
		Short('n').
		BoolVar(&input.NoSession)

	cmd.Arg("profile", "Name of the profile").
		Required().
		HintAction(a.MustGetProfileNames).
		StringVar(&input.ProfileName)

	cmd.Action(func(c *kingpin.ParseContext) (err error) {
		input.Config.MfaPromptMethod = a.PromptDriver(false)
		keyring, err := a.Keyring()
		if err != nil {
			return err
		}
		f, err := a.AwsConfigFile()
		if err != nil {
			return err
		}

		err = RotateCommand(input, f, keyring)
		app.FatalIfError(err, "rotate")
		return nil
	})
}

func RotateCommand(input RotateCommandInput, f *vault.ConfigFile, keyring keyring.Keyring) error {
	// Can't disable sessions completely, might need to use session for MFA-Protected API Access
	vault.UseSession = !input.NoSession
	vault.UseSessionCache = false

	configLoader := vault.NewConfigLoader(input.Config, f, input.ProfileName)
	config, err := configLoader.LoadFromProfile(input.ProfileName)
	if err != nil {
		return fmt.Errorf("Error loading config: %w", err)
	}

	ckr := &vault.CredentialKeyring{Keyring: keyring}
	masterCredentialsName, err := vault.FindMasterCredentialsNameFor(input.ProfileName, ckr, config)
	if err != nil {
		return fmt.Errorf("Error determining credential name for '%s': %w", input.ProfileName, err)
	}

	if input.NoSession {
		fmt.Printf("Rotating credentials stored for profile '%s' using master credentials (takes 10-20 seconds)\n", masterCredentialsName)
	} else {
		fmt.Printf("Rotating credentials stored for profile '%s' using a session from profile '%s' (takes 10-20 seconds)\n", masterCredentialsName, input.ProfileName)
	}

	// Get the existing credentials access key ID
	oldMasterCreds, err := vault.NewMasterCredentialsProvider(ckr, masterCredentialsName).Retrieve(context.TODO())
	if err != nil {
		return fmt.Errorf("Error loading source credentials for '%s': %w", masterCredentialsName, err)
	}
	oldMasterCredsAccessKeyID := vault.FormatKeyForDisplay(oldMasterCreds.AccessKeyID)
	log.Printf("Rotating access key %s\n", oldMasterCredsAccessKeyID)

	fmt.Println("Creating a new access key")

	// create a session to rotate the credentials
	var credsProvider aws.CredentialsProvider
	if input.NoSession {
		credsProvider = vault.NewMasterCredentialsProvider(ckr, config.ProfileName)
	} else {
		credsProvider, err = vault.NewTempCredentialsProvider(config, ckr)
		if err != nil {
			return fmt.Errorf("Error getting temporary credentials: %w", err)
		}
	}

	cfg := vault.NewAwsConfigWithCredsProvider(credsProvider, config.Region, config.STSRegionalEndpoints)

	// A username is needed for some IAM calls if the credentials have assumed a role
	iamUserName, err := getUsernameIfAssumingRole(context.TODO(), cfg, config)
	if err != nil {
		return err
	}

	iamClient := iam.NewFromConfig(cfg)
	// Create a new access key
	createOut, err := iamClient.CreateAccessKey(context.TODO(), &iam.CreateAccessKeyInput{
		UserName: iamUserName,
	})
	if err != nil {
		return fmt.Errorf("Error creating a new access key: %w", err)
	}
	fmt.Printf("Created new access key %s\n", vault.FormatKeyForDisplay(*createOut.AccessKey.AccessKeyId))

	newMasterCreds := aws.Credentials{
		AccessKeyID:     *createOut.AccessKey.AccessKeyId,
		SecretAccessKey: *createOut.AccessKey.SecretAccessKey,
	}

	err = ckr.Set(masterCredentialsName, newMasterCreds)
	if err != nil {
		return fmt.Errorf("Error storing new access key %s: %w", vault.FormatKeyForDisplay(newMasterCreds.AccessKeyID), err)
	}

	// Delete old sessions
	sk := &vault.SessionKeyring{Keyring: ckr.Keyring}
	profileNames, err := getProfilesInChain(input.ProfileName, configLoader)
	for _, profileName := range profileNames {
		if n, _ := sk.RemoveForProfile(profileName); n > 0 {
			fmt.Printf("Deleted %d sessions for %s\n", n, profileName)
		}
	}

	// Use new credentials to delete old access key
	fmt.Printf("Deleting old access key %s\n", oldMasterCredsAccessKeyID)
	err = retry(time.Second*20, time.Second*2, func() error {
		_, err = iamClient.DeleteAccessKey(context.TODO(), &iam.DeleteAccessKeyInput{
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
			return // nolint
		}

		elapsed := time.Since(t0)
		if elapsed > maxTime {
			return fmt.Errorf("After %d attempts, last error: %s", i, err)
		}

		time.Sleep(sleep)
		log.Println("Retrying after error:", err)
	}
}

func getUsernameIfAssumingRole(ctx context.Context, awsCfg aws.Config, config *vault.Config) (*string, error) {
	if config.RoleARN != "" {
		n, err := vault.GetUsernameFromSession(ctx, awsCfg)
		if err != nil {
			return nil, fmt.Errorf("Error getting IAM username from session: %w", err)
		}
		log.Printf("Found IAM username '%s'", n)
		return &n, nil
	}
	return nil, nil //nolint
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
