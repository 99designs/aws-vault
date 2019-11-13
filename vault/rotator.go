package vault

import (
	"fmt"
	"log"
	"time"

	"github.com/99designs/keyring"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/service/iam"
)

func Rotate(profileName string, keyring keyring.Keyring, config *Config) error {
	if profileName != config.CredentialsName {
		return fmt.Errorf("Profile '%s' uses credentials from '%s'. Try rotating '%s' instead", profileName, config.CredentialsName, config.CredentialsName)
	}

	// --------------------------------
	// Get the existing credentials

	keyringProvider := NewKeyringProvider(keyring, config.CredentialsName)
	keyringCredentials := credentials.NewCredentials(keyringProvider)

	oldMasterCreds, err := keyringCredentials.Get()
	if err != nil {
		return err
	}

	vaultCredentials, err := NewVaultCredentials(keyring, config)
	if err != nil {
		return err
	}

	oldCredentialsValue, err := vaultCredentials.Get()
	if err != nil {
		return err
	}
	oldVaultSession := newSession(vaultCredentials, config.Region)

	currentUserName, err := GetUsernameFromSession(oldVaultSession)
	if err != nil {
		return err
	}

	log.Printf("Found old access key ****************%s for user %s",
		oldMasterCreds.AccessKeyID[len(oldMasterCreds.AccessKeyID)-4:],
		currentUserName)

	// --------------------------------
	// Create new access key

	log.Println("Using old credentials to create a new access key")

	var iamUserName *string

	// A username is needed for some IAM calls if the credentials have assumed a role
	if oldCredentialsValue.SessionToken != "" || currentUserName != "root" {
		iamUserName = aws.String(currentUserName)
	}

	createOut, err := iam.New(oldVaultSession).CreateAccessKey(&iam.CreateAccessKeyInput{
		UserName: iamUserName,
	})
	if err != nil {
		return err
	}

	log.Println("Created new access key")

	newMasterCreds := credentials.Value{
		AccessKeyID:     *createOut.AccessKey.AccessKeyId,
		SecretAccessKey: *createOut.AccessKey.SecretAccessKey,
	}

	if err := keyringProvider.Store(newMasterCreds); err != nil {
		return fmt.Errorf("Error storing new access key %v: %v", newMasterCreds.AccessKeyID, err)
	}

	// --------------------------------
	// Delete old sessions

	sessions := NewKeyringSessions(keyring)
	if n, _ := sessions.Delete(profileName); n > 0 {
		log.Printf("Deleted %d existing sessions.", n)
	}

	// expire the credentials
	vaultCredentials.Expire()

	// --------------------------------
	// Use new credentials to delete old access key

	log.Println("Using new credentials to delete the old new access key")
	log.Println("Waiting for new IAM credentials to propagate (takes up to 10 seconds)")

	newIamClient := iam.New(newSession(vaultCredentials, config.Region))

	err = retry(time.Second*20, time.Second*5, func() error {
		_, err = newIamClient.DeleteAccessKey(&iam.DeleteAccessKeyInput{
			AccessKeyId: aws.String(oldMasterCreds.AccessKeyID),
			UserName:    iamUserName,
		})
		return err
	})
	if err != nil {
		return fmt.Errorf("Can't delete old access key %v: %v", oldMasterCreds.AccessKeyID, err)
	}

	log.Printf("Rotated credentials for profile %q in vault", profileName)
	return nil
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
