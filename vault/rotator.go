package vault

import (
	"fmt"
	"log"
	"time"

	"github.com/99designs/keyring"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
)

func getUsernameIfAssumingRole(sess *session.Session, config Config) (*string, error) {
	if config.RoleARN != "" {
		n, err := GetUsernameFromSession(sess)
		if err != nil {
			return nil, err
		}
		log.Printf("Found IAM username '%s'", n)
		return &n, nil
	}
	return nil, nil
}

// Rotate rotates the credentials in config.CredentialsName
func Rotate(keyring keyring.Keyring, config Config) error {

	masterCredsProvider := NewMasterCredentialsProvider(keyring, config.CredentialsName)

	// Get the existing credentials
	oldMasterCreds, err := credentials.NewCredentials(masterCredsProvider).Get()
	if err != nil {
		return err
	}
	log.Printf("Rotating access key %s", formatKeyForDisplay(oldMasterCreds.AccessKeyID))

	// create a session to rotate the credentials
	sessCredsProvider, err := NewCredentialsProvider(keyring, config)
	if err != nil {
		return err
	}
	sessCreds := credentials.NewCredentials(sessCredsProvider)
	sess, err := newSession(sessCreds, config.Region)
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
	log.Printf("Created new access key %s", formatKeyForDisplay(*createOut.AccessKey.AccessKeyId))

	newMasterCreds := credentials.Value{
		AccessKeyID:     *createOut.AccessKey.AccessKeyId,
		SecretAccessKey: *createOut.AccessKey.SecretAccessKey,
	}

	err = masterCredsProvider.Store(newMasterCreds)
	if err != nil {
		return fmt.Errorf("Error storing new access key %v: %v", formatKeyForDisplay(newMasterCreds.AccessKeyID), err)
	}

	// Delete old sessions
	sessions := NewKeyringSessions(keyring)
	if n, _ := sessions.Delete(config.CredentialsName); n > 0 {
		log.Printf("Deleted %d existing sessions.", n)
	}

	// expire the cached credentials
	sessCreds.Expire()

	// Use new credentials to delete old access key
	log.Println("Waiting for new IAM credentials to propagate (takes up to 10 seconds)")
	err = retry(time.Second*30, time.Second*5, func() error {
		_, err = iam.New(sess).DeleteAccessKey(&iam.DeleteAccessKeyInput{
			AccessKeyId: &oldMasterCreds.AccessKeyID,
			UserName:    iamUserName,
		})
		return err
	})
	if err != nil {
		return fmt.Errorf("Can't delete old access key %v: %v", formatKeyForDisplay(oldMasterCreds.AccessKeyID), err)
	}
	log.Printf("Removed old access key %s", formatKeyForDisplay(oldMasterCreds.AccessKeyID))

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
