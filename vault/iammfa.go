package vault

import (
	"encoding/base32"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/mdp/qrterminal"

	"github.com/99designs/aws-vault/mfa"
)

// IAMMfa combines IAM config with a mfa device
type IAMMfa struct {
	IAM           *iam.IAM
	TokenProvider mfa.TokenProvider
	STS           *sts.STS
}

// NewIAMMfa initializes a AWS virtual mfa device as target
func NewIAMMfa(sess *session.Session, tp mfa.TokenProvider) IAMMfa {
	return IAMMfa{
		IAM:           iam.New(sess),
		STS:           sts.New(sess),
		TokenProvider: tp,
	}
}

// Add adds a virtual mfa device for the IAM user
func (m IAMMfa) Add(username, profileName string) error {
	serial, secret, err := m.create(username)

	if err != nil {
		return err
	}

	if err := m.enable(username, serial, secret); err != nil {
		fmt.Printf("error enabling virtual mfa device: %s\n", err.Error())
		fmt.Println("attempting to roll back changes...")
		return m.Delete(username)
	}

	return nil
}

// create creates a virtual mfa device for the IAM user
func (m IAMMfa) create(username string) (*string, []byte, error) {
	fmt.Println("creating virtual mfa device")
	res, err := m.IAM.CreateVirtualMFADevice(&iam.CreateVirtualMFADeviceInput{
		VirtualMFADeviceName: &username,
	})

	if err != nil {
		return nil, nil, fmt.Errorf("error creating virtual device for iam user: %w", err)
	}

	secret, err := base32.StdEncoding.DecodeString(string(res.VirtualMFADevice.Base32StringSeed))

	if err != nil {
		return nil, nil, fmt.Errorf("error decoding secret: %w", err)
	}

	log.Printf("serial: %s", *res.VirtualMFADevice.SerialNumber)

	return res.VirtualMFADevice.SerialNumber, secret, nil
}

func (m IAMMfa) enable(username string, serial *string, secret []byte) error {
	uri := fmt.Sprintf("otpauth://totp/AWS:%s?secret=%s&issuer=AWS&algorithm=SHA1&digits=6&period=30",
		*serial,
		base32.StdEncoding.EncodeToString(secret),
	)

	qrterminal.Generate(uri, qrterminal.L, os.Stderr)

	fmt.Printf("issuer: %s\nname: %s\nsecret: %s\nuri: %s\n\n", "AWS", *serial, base32.StdEncoding.EncodeToString(secret), uri)

	fmt.Println("Add the details to your OTP generator... then we need 2 codes")

	var tries int
	for {
		var err error
		tries += 1

		otp1, err := m.TokenProvider.Retrieve(*serial)
		if err != nil {
			return fmt.Errorf("error getting first otp: %w", err)
		}

		fmt.Println("now a second token")
		otp2, err := m.TokenProvider.Retrieve(*serial)
		if err != nil {
			return fmt.Errorf("error getting second otp: %w", err)
		}

		_, err = m.IAM.EnableMFADevice(&iam.EnableMFADeviceInput{
			AuthenticationCode1: &otp1,
			AuthenticationCode2: &otp2,
			SerialNumber:        serial,
			UserName:            &username,
		})
		if err != nil {
			awsErr, ok := err.(awserr.Error)

			if ok && awsErr.Code() == "InvalidAuthenticationCode" && tries < 3 {
				fmt.Println("Auth codes not valid, let's try again...")
				continue
			}

			return fmt.Errorf("failed to enable virtual mfa device with serial %q: %w", *serial, err)
		}

		fmt.Printf("Virtual mfa device enabled with codes %s and %s\n", otp1, otp2)
		break
	}

	return nil
}

// Delete removes a virtual mfa device from the source including it's association with
// the given IAM username
func (m IAMMfa) Delete(username string) error {
	res, err := m.STS.GetCallerIdentity(&sts.GetCallerIdentityInput{})

	if err != nil {
		return fmt.Errorf("failed to determine serial number for device deletion: %w", err)
	}

	serial, err := callerIdentityToSerial(res.Arn)

	if err != nil {
		return err
	}

	err = m.deactivate(username, &serial)
	if err != nil {
		return err
	}

	if err := m.delete(&serial); err != nil {
		return err
	}

	return nil
}

// deactivate deactivates the virtual MFA device
func (m IAMMfa) deactivate(username string, serial *string) error {
	_, err := m.IAM.DeactivateMFADevice(&iam.DeactivateMFADeviceInput{
		SerialNumber: serial,
		UserName:     &username,
	})

	if err != nil {
		awsErr, ok := err.(awserr.Error)

		if !ok || ok && awsErr.Code() != "NoSuchEntity" {
			return fmt.Errorf("failed to deactivate virtual mfa device with serial %q: %w", *serial, err)
		}
	}

	return nil
}

// delete deletes the virtual MFA device
func (m IAMMfa) delete(serial *string) error {
	_, err := m.IAM.DeleteVirtualMFADevice(&iam.DeleteVirtualMFADeviceInput{
		SerialNumber: serial,
	})

	if err != nil {
		awsErr, ok := err.(awserr.Error)

		if !ok || ok && awsErr.Code() != "NoSuchEntity" {
			return fmt.Errorf("failed to delete virtual AWS IAMYubikey device with serial %q: %w", *serial, err)
		}
	}

	return nil
}

// callerIdentityToSerial converts a caller identity ARN to a MFA serial
func callerIdentityToSerial(i *string) (string, error) {
	a, err := arn.Parse(*i)

	if err != nil {
		return "", fmt.Errorf("failed to parse %q as ARN: %w", *i, err)
	}

	return strings.Replace(a.String(), ":user/", ":mfa/", 1), nil
}
