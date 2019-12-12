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
)

const DefaultExpirationWindow = 5 * time.Minute

func newSession(creds *credentials.Credentials, region string) (*session.Session, error) {
	return session.NewSession(aws.NewConfig().WithRegion(region).WithCredentials(creds))
}

func formatKeyForDisplay(k string) string {
	return fmt.Sprintf("****************%s", k[len(k)-4:])
}

type Mfa struct {
	MfaToken        string
	MfaPromptMethod string
	MfaSerial       string
}

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

func NewMasterCredentials(k keyring.Keyring, credentialsName string) *credentials.Credentials {
	return credentials.NewCredentials(NewMasterCredentialsProvider(k, credentialsName))
}

func NewMasterCredentialsProvider(k keyring.Keyring, credentialsName string) *KeyringProvider {
	return &KeyringProvider{k, credentialsName}
}

// NewTempCredentials creates temporary credentials
func NewTempCredentials(k keyring.Keyring, config *Config) (*credentials.Credentials, error) {
	provider, err := NewTempCredentialsProvider(k, config)
	if err != nil {
		return nil, err
	}

	return credentials.NewCredentials(provider), nil
}

func NewSessionTokenProvider(creds *credentials.Credentials, k keyring.Keyring, config *Config) *SessionTokenProvider {
	return &SessionTokenProvider{
		MasterCreds:     creds,
		Sessions:        NewKeyringSessions(k),
		CredentialsName: config.CredentialsName,
		Duration:        config.GetSessionTokenDuration,
		Region:          config.Region,
		Mfa: Mfa{
			MfaToken:        config.MfaToken,
			MfaPromptMethod: config.MfaPromptMethod,
			MfaSerial:       config.MfaSerial,
		},
	}
}

func NewAssumeRoleProvider(creds *credentials.Credentials, config *Config) *AssumeRoleProvider {
	return &AssumeRoleProvider{
		Creds:           creds,
		RoleARN:         config.RoleARN,
		RoleSessionName: config.RoleSessionName,
		Region:          config.Region,
		ExternalID:      config.ExternalID,
		Duration:        config.AssumeRoleDuration,
		Mfa: Mfa{
			MfaSerial:       config.MfaSerial,
			MfaToken:        config.MfaToken,
			MfaPromptMethod: config.MfaPromptMethod,
		},
	}
}

// NewTempCredentialsProvider creates a provider for temporary credentials
func NewTempCredentialsProvider(k keyring.Keyring, config *Config) (credentials.Provider, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	masterCredsProvider := NewMasterCredentialsProvider(k, config.CredentialsName)

	if config.NoSession && config.RoleARN == "" {
		log.Println("Using master credentials")
		return masterCredsProvider, nil
	}

	if config.NoSession {
		return NewAssumeRoleProvider(credentials.NewCredentials(masterCredsProvider), config), nil
	}

	sessionTokenCredsProvider := NewSessionTokenProvider(credentials.NewCredentials(masterCredsProvider), k, config)

	if config.RoleARN == "" {
		return sessionTokenCredsProvider, nil
	}

	return NewAssumeRoleProvider(credentials.NewCredentials(sessionTokenCredsProvider), config), nil
}
