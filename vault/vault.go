package vault

import (
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/99designs/aws-vault/prompt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sso"
	"github.com/aws/aws-sdk-go/service/ssooidc"
	"github.com/aws/aws-sdk-go/service/sts"
)

const defaultExpirationWindow = 5 * time.Minute

var UseSessionCache = true

func NewSession(creds *credentials.Credentials, region string) (*session.Session, error) {
	return session.NewSessionWithOptions(session.Options{
		Config: aws.Config{
			Region:      aws.String(region),
			Credentials: creds,
		},
		SharedConfigState: session.SharedConfigDisable,
	})
}

func FormatKeyForDisplay(k string) string {
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
func NewMasterCredentialsProvider(k *CredentialKeyring, credentialsName string) *KeyringProvider {
	return &KeyringProvider{k, credentialsName}
}

func NewMasterCredentials(k *CredentialKeyring, credentialsName string) *credentials.Credentials {
	return credentials.NewCredentials(NewMasterCredentialsProvider(k, credentialsName))
}

func NewSessionTokenProvider(creds *credentials.Credentials, k *CredentialKeyring, config *Config) (credentials.Provider, error) {
	sess, err := NewSession(creds, config.Region)
	if err != nil {
		return nil, err
	}

	sessionTokenProvider := &SessionTokenProvider{
		StsClient:    sts.New(sess),
		Duration:     config.GetSessionTokenDuration(),
		ExpiryWindow: defaultExpirationWindow,
		Mfa: Mfa{
			MfaToken:        config.MfaToken,
			MfaPromptMethod: config.MfaPromptMethod,
			MfaSerial:       config.MfaSerial,
		},
	}

	if UseSessionCache {
		return &CachedSessionTokenProvider{
			Keyring:         k,
			CredentialsName: config.ProfileName,
			ExpiryWindow:    defaultExpirationWindow,
			Provider:        sessionTokenProvider,
		}, nil
	}

	return sessionTokenProvider, nil
}

// NewAssumeRoleProvider returns a provider that generates credentials using AssumeRole
func NewAssumeRoleProvider(creds *credentials.Credentials, config *Config) (*AssumeRoleProvider, error) {
	sess, err := NewSession(creds, config.Region)
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

// NewSSORoleCredentialsProvider creates a provider for SSO credentials
func NewSSORoleCredentialsProvider(k *CredentialKeyring, config *Config) (credentials.Provider, error) {
	sess, err := session.NewSession(&aws.Config{Region: aws.String(config.SSORegion)})
	if err != nil {
		return nil, err
	}

	ssoOIDCProvider := &SSOOIDCProvider{
		Keyring:    k,
		OIDCClient: ssooidc.New(sess),
		StartURL:   config.SSOStartURL,
	}

	ssoRoleCredentialsProvider := &SSORoleCredentialsProvider{
		OIDCProvider: ssoOIDCProvider,
		SSOClient:    sso.New(sess),
		AccountID:    config.SSOAccountID,
		RoleName:     config.SSORoleName,
		ExpiryWindow: defaultExpirationWindow,
	}

	if UseSessionCache {
		return &CachedSSORoleCredentialsProvider{
			CredentialsName: config.ProfileName,
			Keyring:         k,
			ExpiryWindow:    defaultExpirationWindow,
			Provider:        ssoRoleCredentialsProvider,
		}, nil
	}

	return ssoRoleCredentialsProvider, nil
}

type tempCredsCreator struct {
	keyring    *CredentialKeyring
	chainedMfa string
}

func (t *tempCredsCreator) provider(config *Config) (credentials.Provider, error) {
	var sourceCredProvider credentials.Provider

	hasStoredCredentials, err := t.keyring.Has(config.ProfileName)
	if err != nil {
		return nil, err
	}

	if hasStoredCredentials && config.HasSourceProfile() {
		return nil, fmt.Errorf("profile %s: have stored credentials but source_profile is defined", config.ProfileName)
	} else if hasStoredCredentials {
		log.Printf("profile %s: using stored credentials", config.ProfileName)
		sourceCredProvider = NewMasterCredentialsProvider(t.keyring, config.ProfileName)
	} else if config.HasSourceProfile() {
		sourceCredProvider, err = t.provider(config.SourceProfile)
		if err != nil {
			return nil, err
		}
	} else if config.HasSSOStartURL() {
		return NewSSORoleCredentialsProvider(t.keyring, config)
	} else {
		return nil, fmt.Errorf("profile %s: credentials missing", config.ProfileName)
	}

	if hasStoredCredentials || !config.HasRole() {
		if canUseGetSessionToken, reason := config.CanUseGetSessionToken(); !canUseGetSessionToken {
			log.Printf("profile %s: skipping GetSessionToken because %s", config.ProfileName, reason)
			if !config.HasRole() {
				return sourceCredProvider, nil
			}
		}

		t.chainedMfa = config.MfaSerial
		log.Printf("profile %s: using GetSessionToken %s", config.ProfileName, mfaDetails(false, config))
		sourceCredProvider, err = NewSessionTokenProvider(credentials.NewCredentials(sourceCredProvider), t.keyring, config)
		if !config.HasRole() || err != nil {
			return sourceCredProvider, err
		}
	}

	isMfaChained := config.MfaSerial != "" && config.MfaSerial == t.chainedMfa
	if isMfaChained {
		config.MfaSerial = ""
	}

	log.Printf("profile %s: using AssumeRole %s", config.ProfileName, mfaDetails(isMfaChained, config))
	return NewAssumeRoleProvider(credentials.NewCredentials(sourceCredProvider), config)
}

func mfaDetails(mfaChained bool, config *Config) string {
	if mfaChained {
		return "(chained MFA)"
	}
	if config.HasMfaSerial() {
		return "(with MFA)"
	}
	return ""
}

// NewTempCredentialsProvider creates a credential provider for the given config
func NewTempCredentialsProvider(config *Config, keyring *CredentialKeyring) (credentials.Provider, error) {
	t := tempCredsCreator{
		keyring: keyring,
	}
	return t.provider(config)
}

// NewTempCredentials returns credentials for the given config
func NewTempCredentials(config *Config, k *CredentialKeyring) (*credentials.Credentials, error) {
	provider, err := NewTempCredentialsProvider(config, k)
	if err != nil {
		return nil, err
	}

	return credentials.NewCredentials(provider), nil
}

func NewFederationTokenCredentials(profileName string, k *CredentialKeyring, config *Config) (*credentials.Credentials, error) {
	credentialsName, err := MasterCredentialsFor(profileName, k, config)
	if err != nil {
		return nil, err
	}

	sess, err := NewSession(NewMasterCredentials(k, credentialsName), config.Region)
	if err != nil {
		return nil, err
	}

	currentUsername, err := GetUsernameFromSession(sess)
	if err != nil {
		return nil, err
	}

	log.Printf("Using GetFederationToken for credentials")
	return credentials.NewCredentials(&FederationTokenProvider{
		StsClient: sts.New(sess),
		Name:      currentUsername,
		Duration:  config.GetFederationTokenDuration,
	}), nil
}

func MasterCredentialsFor(profileName string, keyring *CredentialKeyring, config *Config) (string, error) {
	hasMasterCreds, err := keyring.Has(profileName)
	if err != nil {
		return "", err
	}

	if hasMasterCreds {
		return profileName, nil
	}

	return MasterCredentialsFor(config.SourceProfileName, keyring, config)
}
