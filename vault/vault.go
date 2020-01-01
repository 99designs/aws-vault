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
	"github.com/aws/aws-sdk-go/service/sts"
)

const defaultExpirationWindow = 5 * time.Minute

var UseSessionCache = true

func NewSession(creds *credentials.Credentials, region string) (*session.Session, error) {
	return session.NewSession(aws.NewConfig().WithRegion(region).WithCredentials(creds))
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

func NewSessionTokenProvider(creds *credentials.Credentials, k *CredentialKeyring, config Config) (credentials.Provider, error) {
	sess, err := NewSession(creds, config.Region)
	if err != nil {
		return nil, err
	}

	sessionTokenProvider := &SessionTokenProvider{
		StsClient:    sts.New(sess),
		Duration:     config.GetSessionTokenDuration,
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
func NewAssumeRoleProvider(creds *credentials.Credentials, config Config) (*AssumeRoleProvider, error) {
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

type CredentialLoader struct {
	Keyring      *CredentialKeyring
	ConfigLoader *ConfigLoader
}

// Provider creates a credential provider for the given config
func (c *CredentialLoader) Provider(profileName string) (credentials.Provider, error) {
	return c.ProviderWithChainedMfa(profileName, false, "")
}

var errChainedMfaNotMatched = errors.New("Chained MFA serial didn't match")

// Provider creates a credential provider for the given config. To chain the MFA serial with a source credential, pass the MFA serial in chainMfaSerial
func (c *CredentialLoader) ProviderWithChainedMfa(profileName string, isChained bool, chainedMfaSerial string) (credentials.Provider, error) {
	config, err := c.ConfigLoader.LoadFromProfile(profileName)
	if err != nil {
		return nil, err
	}

	if chainedMfaSerial != "" && config.MfaSerial != "" && chainedMfaSerial != config.MfaSerial {
		return nil, errChainedMfaNotMatched
	}

	useChainedMfa := true
	var sourceCredProvider credentials.Provider

	hasMasterCredentials, err := c.Keyring.Has(config.ProfileName)
	if err != nil {
		return nil, err
	}

	if hasMasterCredentials {
		log.Printf("profile %s: using stored credentials", profileName)
		sourceCredProvider = NewMasterCredentialsProvider(c.Keyring, config.ProfileName)
	} else if config.SourceProfile != "" {
		sourceCredProvider, err = c.ProviderWithChainedMfa(config.SourceProfile, true, config.MfaSerial)
		if err == errChainedMfaNotMatched {
			useChainedMfa = false
			sourceCredProvider, err = c.ProviderWithChainedMfa(config.SourceProfile, true, "")
		}
		if err != nil {
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("profile %s: credentials missing", profileName)
	}

	sourceCreds := credentials.NewCredentials(sourceCredProvider)
	if config.RoleARN == "" {

		if isChained {
			if chainedMfaSerial == "" {
				log.Printf("profile %s: MFA is not present in the chained profile, getting session without MFA", profileName)
				config.MfaSerial = ""
			}

			config.GetSessionTokenDuration = config.ChainedGetSessionTokenDuration
		}

		log.Printf("profile %s: using GetSessionToken", profileName)
		return NewSessionTokenProvider(sourceCreds, c.Keyring, config)
	}

	if useChainedMfa {
		log.Printf("profile %s: MFA already used in source profile, assuming role without MFA", profileName)
		config.MfaSerial = ""
	}

	log.Printf("profile %s: using AssumeRole", profileName)
	return NewAssumeRoleProvider(sourceCreds, config)
}

func NewTempCredentialsProvider(profileName string, k *CredentialKeyring, configLoader *ConfigLoader) (credentials.Provider, error) {
	cl := CredentialLoader{
		Keyring:      k,
		ConfigLoader: configLoader,
	}

	return cl.Provider(profileName)
}

// NewTempCredentials returns credentials for the given config
func NewTempCredentials(profileName string, k *CredentialKeyring, cl *ConfigLoader) (*credentials.Credentials, error) {
	provider, err := NewTempCredentialsProvider(profileName, k, cl)
	if err != nil {
		return nil, err
	}

	return credentials.NewCredentials(provider), nil
}

func NewFederationTokenCredentials(profileName string, k *CredentialKeyring, configLoader *ConfigLoader) (*credentials.Credentials, error) {
	config, err := configLoader.LoadFromProfile(profileName)
	if err != nil {
		return nil, err
	}

	credentialsName, err := MasterCredentialsFor(profileName, k, configLoader)
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

func MasterCredentialsFor(profileName string, keyring *CredentialKeyring, configLoader *ConfigLoader) (string, error) {
	hasMasterCreds, err := keyring.Has(profileName)
	if err != nil {
		return "", err
	}

	if hasMasterCreds {
		return profileName, nil
	}

	config, err := configLoader.LoadFromProfile(profileName)
	if err != nil {
		return "", err
	}

	return MasterCredentialsFor(config.SourceProfile, keyring, configLoader)
}
