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
)

// Yubikey represents a yubikey config
type Yubikey struct {
	Keyring  keyring.Keyring
	Username string
	Config   *Config
}

// Create adds a yubikey as a device device for an iam user and stores the config in a keychain
func (y *Yubikey) Register(profile string) error {
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

	cb := func(name string) error {
		log.Println("waiting for yubikey touch...")
		return nil
	}
	device, err := yubikey.New(cb)
	if err != nil {
		return err
	}

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

	qrterminal.GenerateHalfBlock(uri, qrterminal.L, os.Stderr)

	if serial != nil {
		log.Println("success:", *serial)
	}

	return nil
}

// Remove removes yubikey as mfa device from AWS then otp config from yubikey
func (y *Yubikey) Remove(profile string) error {
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

	cb := func(name string) error {
		log.Println("waiting for yubikey touch...")
		return nil
	}
	device, err := yubikey.New(cb)
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

	return nil
}
