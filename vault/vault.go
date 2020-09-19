package vault

import (
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/99designs/aws-vault/v6/prompt"
	"github.com/99designs/keyring"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sso"
	"github.com/aws/aws-sdk-go/service/ssooidc"
	"github.com/aws/aws-sdk-go/service/sts"
)

var defaultExpirationWindow = 5 * time.Minute

func init() {
	if d, err := time.ParseDuration(os.Getenv("AWS_MIN_TTL")); err == nil {
		defaultExpirationWindow = d
	}
}

var UseSessionCache = true

func NewSession(region, stsRegionalEndpoints string) (*session.Session, error) {
	endpointConfig, err := endpoints.GetSTSRegionalEndpoint(stsRegionalEndpoints)
	if err != nil && stsRegionalEndpoints != "" {
		return nil, err
	}

	return session.NewSessionWithOptions(session.Options{
		Config: aws.Config{
			Region:              aws.String(region),
			STSRegionalEndpoint: endpointConfig,
		},
		SharedConfigState: session.SharedConfigDisable,
	})
}

func NewSessionWithCreds(creds *credentials.Credentials, region, stsRegionalEndpoints string) (*session.Session, error) {
	s, err := NewSession(region, stsRegionalEndpoints)
	if err != nil {
		return nil, err
	}
	s.Config.Credentials = creds

	return s, nil
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
		token, err := promptFunc(m.MfaSerial)
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

func NewSessionTokenProvider(creds *credentials.Credentials, k keyring.Keyring, config *Config) (credentials.Provider, error) {
	sess, err := NewSessionWithCreds(creds, config.Region, config.STSRegionalEndpoints)
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
		return &CachedSessionProvider{
			SessionKey: SessionMetadata{
				Type:        "sts.GetSessionToken",
				ProfileName: config.ProfileName,
				MfaSerial:   config.MfaSerial,
			},
			Keyring:         &SessionKeyring{Keyring: k},
			ExpiryWindow:    defaultExpirationWindow,
			CredentialsFunc: sessionTokenProvider.GetSessionToken,
		}, nil
	}

	return sessionTokenProvider, nil
}

// NewAssumeRoleProvider returns a provider that generates credentials using AssumeRole
func NewAssumeRoleProvider(creds *credentials.Credentials, k keyring.Keyring, config *Config) (credentials.Provider, error) {
	sess, err := NewSessionWithCreds(creds, config.Region, config.STSRegionalEndpoints)
	if err != nil {
		return nil, err
	}

	p := &AssumeRoleProvider{
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
	}

	if UseSessionCache && config.MfaSerial != "" {
		return &CachedSessionProvider{
			SessionKey: SessionMetadata{
				Type:        "sts.AssumeRole",
				ProfileName: config.ProfileName,
				MfaSerial:   config.MfaSerial,
			},
			Keyring:         &SessionKeyring{Keyring: k},
			ExpiryWindow:    defaultExpirationWindow,
			CredentialsFunc: p.assumeRole,
		}, nil
	}

	return p, nil
}

// NewAssumeRoleWithWebIdentityProvider returns a provider that generates
// credentials using AssumeRoleWithWebIdentity
func NewAssumeRoleWithWebIdentityProvider(k keyring.Keyring, config *Config) (credentials.Provider, error) {
	sess, err := NewSession(config.Region, config.STSRegionalEndpoints)
	if err != nil {
		return nil, err
	}

	p := &AssumeRoleWithWebIdentityProvider{
		StsClient:               sts.New(sess),
		RoleARN:                 config.RoleARN,
		RoleSessionName:         config.RoleSessionName,
		WebIdentityTokenFile:    config.WebIdentityTokenFile,
		WebIdentityTokenProcess: config.WebIdentityTokenProcess,
		Duration:                config.AssumeRoleDuration,
		ExpiryWindow:            defaultExpirationWindow,
	}

	if UseSessionCache {
		return &CachedSessionProvider{
			SessionKey: SessionMetadata{
				Type:        "sts.AssumeRoleWithWebIdentity",
				ProfileName: config.ProfileName,
			},
			Keyring:         &SessionKeyring{Keyring: k},
			ExpiryWindow:    defaultExpirationWindow,
			CredentialsFunc: p.assumeRole,
		}, nil
	}

	return p, nil
}

// NewSSORoleCredentialsProvider creates a provider for SSO credentials
func NewSSORoleCredentialsProvider(k keyring.Keyring, config *Config) (credentials.Provider, error) {
	sess, err := NewSession(config.SSORegion, config.STSRegionalEndpoints)
	if err != nil {
		return nil, err
	}

	ssoRoleCredentialsProvider := &SSORoleCredentialsProvider{
		OIDCClient:   ssooidc.New(sess),
		StartURL:     config.SSOStartURL,
		SSOClient:    sso.New(sess),
		AccountID:    config.SSOAccountID,
		RoleName:     config.SSORoleName,
		ExpiryWindow: defaultExpirationWindow,
	}

	if UseSessionCache {
		ssoRoleCredentialsProvider.OIDCTokenCache = OIDCTokenKeyring{Keyring: k}
		return &CachedSessionProvider{
			SessionKey: SessionMetadata{
				Type:        "sso.GetRoleCredentials",
				ProfileName: config.ProfileName,
				MfaSerial:   config.SSOStartURL,
			},
			Keyring:         &SessionKeyring{Keyring: k},
			ExpiryWindow:    defaultExpirationWindow,
			CredentialsFunc: ssoRoleCredentialsProvider.getRoleCredentialsAsStsCredemtials,
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
		return NewSSORoleCredentialsProvider(t.keyring.Keyring, config)
	} else if config.HasRole() && (config.HasWebIdentityTokenFile() || config.HasWebIdentityTokenProcess()) {
		return NewAssumeRoleWithWebIdentityProvider(t.keyring.Keyring, config)
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
		sourceCredProvider, err = NewSessionTokenProvider(credentials.NewCredentials(sourceCredProvider), t.keyring.Keyring, config)
		if !config.HasRole() || err != nil {
			return sourceCredProvider, err
		}
	}

	isMfaChained := config.MfaSerial != "" && config.MfaSerial == t.chainedMfa
	if isMfaChained {
		config.MfaSerial = ""
	}

	log.Printf("profile %s: using AssumeRole %s", config.ProfileName, mfaDetails(isMfaChained, config))
	return NewAssumeRoleProvider(credentials.NewCredentials(sourceCredProvider), t.keyring.Keyring, config)
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

	masterCreds := NewMasterCredentials(k, credentialsName)
	sess, err := NewSessionWithCreds(masterCreds, config.Region, config.STSRegionalEndpoints)
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

	if profileName == config.SourceProfileName {
		return "", fmt.Errorf("No master credentials found")
	}

	return MasterCredentialsFor(config.SourceProfileName, keyring, config)
}
