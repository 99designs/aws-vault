package vault

import (
	"encoding/base32"
	"fmt"
	"log"
	"os"

	"github.com/99designs/aws-vault/mfa"
	"github.com/99designs/aws-vault/mfa/device/yubikey"
	"github.com/99designs/keyring"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/mdp/qrterminal"
	"github.com/pkg/errors"
)

// Yubikey represents a yubikey config
type Yubikey struct {
	Keyring  keyring.Keyring
	Username string
	Config   *Config
}

// Create adds a yubikey as a device device for an iam user and stores the config in a keychain
func (y *Yubikey) Register(profile string, requireTouch bool) error {
	var err error

	source, _ := y.Config.SourceProfile(profile)

	provider := &KeyringProvider{
		Keyring: y.Keyring,
		Profile: source.Name,
		Region:  source.Region,
	}

	masterCreds, err := provider.Retrieve()
	if err != nil {
		return err
	}

	sess := session.New(&aws.Config{Region: aws.String(provider.Region),
		Credentials: credentials.NewCredentials(&credentials.StaticProvider{Value: masterCreds}),
	})

	currentUserName, err := GetUsernameFromSession(sess)
	if err != nil {
		return err
	}

	log.Printf("Found access key  ****************%s for user %s",
		masterCreds.AccessKeyID[len(masterCreds.AccessKeyID)-4:],
		currentUserName)

	device, err := yubikey.New()
	if err != nil {
		return err
	}
	device.RequireAddTouch(requireTouch)

	m, err := mfa.New(sess, device)
	if err != nil {
		return err
	}

	serial, secret, err := m.Add(y.Username)
	if err != nil {
		return err
	}

	uri := fmt.Sprintf("otpauth://totp/%s@%s?secret=%s&issuer=%s",
		y.Username,
		source.Name,
		base32.StdEncoding.EncodeToString(secret),
		"Amazon",
	)

	qrterminal.Generate(uri, qrterminal.L, os.Stderr)

	if serial != nil {
		log.Println("success:", *serial)
	}

	return nil
}

// Remove removes yubikey as mfa device from AWS, then otp config from yubikey, then cached session
func (y *Yubikey) Remove(profile string, val credentials.Value) error {
	var err error

	source, _ := y.Config.SourceProfile(profile)

	sess := session.New(&aws.Config{Region: aws.String(source.Region),
		Credentials: credentials.NewCredentials(&credentials.StaticProvider{Value: val}),
	})

	currentUserName, err := GetUsernameFromSession(sess)
	if err != nil {
		return err
	}

	log.Printf("Found access key  ****************%s for user %s",
		val.AccessKeyID[len(val.AccessKeyID)-4:],
		currentUserName)

	device, err := yubikey.New()
	if err != nil {
		return err
	}

	m, err := mfa.New(sess, device)
	if err != nil {
		return err
	}

	if err := m.Delete(y.Username); err != nil {
		return err
	}

	// now delete the session we just used that was created using TOTP from the deleted yubikey
	// other sessions that used a TOTP from the yubikey may still be cached but there's not much
	// we can do about that
	krs, err := NewKeyringSessions(y.Keyring, y.Config)
	if err != nil {
		return errors.Wrap(err, "unable to create keyring sessions")
	}

	n, err := krs.Delete(profile)
	if err != nil {
		return errors.Wrapf(err, "unable to delete keyring session for %s", profile)
	}

	if n == 1 {
		log.Printf("deleted session for '%s'", profile)
	}
	if n > 1 {
		// this shouldn't be possible
		log.Printf("deleted %d sessions for '%s' ", n, profile)
	}

	return nil
}
