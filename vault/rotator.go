package vault

import (
	"fmt"
	"log"
	"time"

	"github.com/99designs/aws-vault/prompt"
	"github.com/99designs/keyring"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
)

type Rotator struct {
	Keyring   keyring.Keyring
	MfaToken  string
	MfaSerial string
	MfaPrompt prompt.PromptFunc
	Config    *Config
}

// Rotate creates a new key and deletes the old one
func (r *Rotator) Rotate(profileName string) error {
	var err error

	source, _ := r.Config.SourceProfile(profileName)

	// --------------------------------
	// Get the existing credentials

	provider := &KeyringProvider{
		Keyring: r.Keyring,
		Profile: source.Name,
		Region:  source.Region,
	}

	oldMasterCreds, err := provider.Retrieve()
	if err != nil {
		return err
	}

	oldSess := session.New(&aws.Config{Region: aws.String(provider.Region),
		Credentials: credentials.NewCredentials(&credentials.StaticProvider{Value: oldMasterCreds}),
	})

	currentUserName, err := GetUsernameFromSession(oldSess)
	if err != nil {
		return err
	}

	log.Printf("Found old access key  ****************%s for user %s",
		oldMasterCreds.AccessKeyID[len(oldMasterCreds.AccessKeyID)-4:],
		currentUserName)

	oldSessionCreds, err := NewVaultCredentials(r.Keyring, profileName, VaultOptions{
		MfaToken:    r.MfaToken,
		MfaSerial:   r.MfaSerial,
		MfaPrompt:   r.MfaPrompt,
		Config:      r.Config,
		NoSession:   !r.needsSessionToRotate(profileName),
		MasterCreds: &oldMasterCreds,
	})
	if err != nil {
		return err
	}

	oldSessionVal, err := oldSessionCreds.Get()
	if err != nil {
		return err
	}

	// --------------------------------
	// Create new access key

	log.Println("Using old credentials to create a new access key")

	var iamUserName *string

	// A username is needed for some IAM calls if the credentials have assumed a role
	if oldSessionVal.SessionToken != "" || currentUserName != "root" {
		iamUserName = aws.String(currentUserName)
	}

	oldSessionClient := iam.New(session.New(&aws.Config{Region: aws.String(provider.Region),
		Credentials: credentials.NewCredentials(&credentials.StaticProvider{Value: oldSessionVal}),
	}))

	createOut, err := oldSessionClient.CreateAccessKey(&iam.CreateAccessKeyInput{
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

	if err := provider.Store(newMasterCreds); err != nil {
		return fmt.Errorf("Error storing new access key %v: %v",
			newMasterCreds.AccessKeyID, err)
	}

	// --------------------------------
	// Use new credentials to delete old access key

	log.Println("Using new credentials to delete the old new access key")

	newSessionCreds, err := NewVaultCredentials(r.Keyring, profileName, VaultOptions{
		MfaToken:    r.MfaToken,
		MfaSerial:   r.MfaSerial,
		MfaPrompt:   r.MfaPrompt,
		Config:      r.Config,
		NoSession:   !r.needsSessionToRotate(profileName),
		MasterCreds: &newMasterCreds,
	})
	if err != nil {
		return err
	}

	log.Printf("Waiting for new IAM credentials to propagate (takes up to 10 seconds)")

	err = retry(time.Second*20, time.Second*5, func() error {
		newVal, err := newSessionCreds.Get()
		if err != nil {
			return err
		}

		newClient := iam.New(session.New(&aws.Config{Region: aws.String(provider.Region),
			Credentials: credentials.NewCredentials(&credentials.StaticProvider{Value: newVal}),
		}))

		_, err = newClient.DeleteAccessKey(&iam.DeleteAccessKeyInput{
			AccessKeyId: aws.String(oldMasterCreds.AccessKeyID),
			UserName:    iamUserName,
		})
		return err
	})

	if err != nil {
		return fmt.Errorf("Can't delete old access key %v: %v", oldMasterCreds.AccessKeyID, err)
	}

	// --------------------------------
	// Delete old sessions

	sessions, err := NewKeyringSessions(r.Keyring, r.Config)
	if err != nil {
		return err
	}

	if n, _ := sessions.Delete(profileName); n > 0 {
		log.Printf("Deleted %d existing sessions.", n)
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

// needsSessionToRotate attempts to resolve the dilemma around whether or not
// profiles should use a session to be able to rotate.
//
// Some profiles require assuming a role to get permission to create new
// credentials.  Alas, others which don't use a role are pure IAM and will
// fail to create credentials when using an STS role, because AWS's IAM
// systems hard-fail early when given STS credentials.
//
// This is a heuristic which might need to continue to evolve.  :(
func (r *Rotator) needsSessionToRotate(profileName string) bool {
	if r.MfaToken != "" {
		return true
	}
	if r.MfaSerial != "" {
		return true
	}
	sourceProfile, known := r.Config.SourceProfile(profileName)
	if !known {
		// best guess
		return false
	}
	if sourceProfile.Name != profileName {
		// TODO: should this comparison be case-insensitive?
		return true
	}
	if sourceProfile.MFASerial != "" {
		return true
	}
	return false
}
