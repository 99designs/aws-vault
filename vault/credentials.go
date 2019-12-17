package vault

import (
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/99designs/aws-vault/prompt"
	"github.com/99designs/keyring"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
)

const defaultExpirationWindow = 5 * time.Minute

func newSession(creds *credentials.Credentials, region string) (*session.Session, error) {
	return session.NewSession(aws.NewConfig().WithRegion(region).WithCredentials(creds))
}

func formatKeyForDisplay(k string) string {
	return fmt.Sprintf("****************%s", k[len(k)-4:])
}

// Mfa contains options for an MFA device
type Mfa struct {
	MfaToken        string
	MfaPromptMethod string
	MfaSerial       string
}

// GetMfaToken returns the MFA token
func (m *Mfa) GetMfaToken() (*string, error) {
	if m.MfaToken != "" {
		return aws.String(m.MfaToken), nil
	}

	if m.MfaPromptMethod != "" {
		promptFunc := prompt.Method(m.MfaPromptMethod)
		token, err := promptFunc(fmt.Sprintf("Enter token for %s: ", m.MfaSerial))
		return aws.String(token), err
	}

	return nil, errors.New("No prompt found")
}

// NewMasterCredentialsProvider creates a provider for the master credentials
func NewMasterCredentialsProvider(k keyring.Keyring, credentialsName string) *KeyringProvider {
	return &KeyringProvider{k, credentialsName}
}

func NewCachedSessionTokenProvider(creds *credentials.Credentials, k keyring.Keyring, config Config) (*CachedSessionTokenProvider, error) {
	sess, err := newSession(creds, config.Region)
	if err != nil {
		return nil, err
	}

	return &CachedSessionTokenProvider{
		Keyring:         k,
		CredentialsName: config.CredentialsName,
		ExpiryWindow:    defaultExpirationWindow,
		Provider: &SessionTokenProvider{
			StsClient:    sts.New(sess),
			Duration:     config.GetSessionTokenDuration,
			ExpiryWindow: defaultExpirationWindow,
			Mfa: Mfa{
				MfaToken:        config.MfaToken,
				MfaPromptMethod: config.MfaPromptMethod,
				MfaSerial:       config.MfaSerial,
			},
		},
	}, nil
}

// NewAssumeRoleProvider returns a provider that generates credentials using AssumeRole
func NewAssumeRoleProvider(creds *credentials.Credentials, config Config) (*AssumeRoleProvider, error) {
	sess, err := newSession(creds, config.Region)
	if err != nil {
		return nil, err
	}

	return &AssumeRoleProvider{
		StsClient:       sts.New(sess),
		RoleARN:         config.RoleARN,
		RoleSessionName: config.RoleSessionName,
		ExternalID:      config.ExternalID,
		Duration:        config.AssumeRoleDuration,
		ExpiryWindow:    defaultExpirationWindow,
		Mfa: Mfa{
			MfaSerial:       config.MfaSerial,
			MfaToken:        config.MfaToken,
			MfaPromptMethod: config.MfaPromptMethod,
		},
	}, nil
}

// NewCredentialsProvider creates a credential provider for the given config.
func NewCredentialsProvider(k keyring.Keyring, config Config) (credentials.Provider, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	masterCredsProvider := NewMasterCredentialsProvider(k, config.CredentialsName)

	if config.NoSession && config.RoleARN == "" {
		log.Println("Using master credentials")
		return masterCredsProvider, nil
	}

	masterCreds := credentials.NewCredentials(masterCredsProvider)

	if config.NoSession {
		log.Println("Using AssumeRole for credentials")
		return NewAssumeRoleProvider(masterCreds, config)
	}

	sessionTokenCredsProvider, err := NewCachedSessionTokenProvider(masterCreds, k, config)
	if err != nil {
		return nil, err
	}

	if config.RoleARN == "" {
		log.Println("Using GetSessionToken for credentials")
		return sessionTokenCredsProvider, nil
	}

	// If assuming a role using a SessionToken, MFA has already been used in the SessionToken
	// and is not required for the AssumeRole call
	config.MfaSerial = ""

	log.Println("Using GetSessionToken + AssumeRole for credentials")
	return NewAssumeRoleProvider(credentials.NewCredentials(sessionTokenCredsProvider), config)
}

// NewCredentials returns credentials for the given config
func NewCredentials(k keyring.Keyring, config Config) (*credentials.Credentials, error) {
	provider, err := NewCredentialsProvider(k, config)
	if err != nil {
		return nil, err
	}

	return credentials.NewCredentials(provider), nil
}
