package vault

import (
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/99designs/aws-vault/v6/prompt"
	"github.com/99designs/keyring"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sso"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

var defaultExpirationWindow = 5 * time.Minute

func init() {
	if d, err := time.ParseDuration(os.Getenv("AWS_MIN_TTL")); err == nil {
		defaultExpirationWindow = d
	}
}

var UseSessionCache = true

func NewAwsConfig(region, stsRegionalEndpoints string) aws.Config {
	return aws.Config{
		Region:           region,
		EndpointResolver: getSTSEndpointResolver(stsRegionalEndpoints),
	}
}

func NewAwsConfigWithCredsProvider(credsProvider aws.CredentialsProvider, region, stsRegionalEndpoints string) aws.Config {
	return aws.Config{
		Region:           region,
		Credentials:      credsProvider,
		EndpointResolver: getSTSEndpointResolver(stsRegionalEndpoints),
	}
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

func NewSessionTokenProvider(credsProvider aws.CredentialsProvider, k keyring.Keyring, config *Config) (aws.CredentialsProvider, error) {
	cfg := NewAwsConfigWithCredsProvider(credsProvider, config.Region, config.STSRegionalEndpoints)

	sessionTokenProvider := &SessionTokenProvider{
		StsClient: sts.NewFromConfig(cfg),
		Duration:  config.GetSessionTokenDuration(),
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
func NewAssumeRoleProvider(credsProvider aws.CredentialsProvider, k keyring.Keyring, config *Config) (aws.CredentialsProvider, error) {
	cfg := NewAwsConfigWithCredsProvider(credsProvider, config.Region, config.STSRegionalEndpoints)

	p := &AssumeRoleProvider{
		StsClient:         sts.NewFromConfig(cfg),
		RoleARN:           config.RoleARN,
		RoleSessionName:   config.RoleSessionName,
		ExternalID:        config.ExternalID,
		Duration:          config.AssumeRoleDuration,
		Tags:              config.SessionTags,
		TransitiveTagKeys: config.TransitiveSessionTags,
		SourceIdentity:    config.SourceIdentity,
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
func NewAssumeRoleWithWebIdentityProvider(k keyring.Keyring, config *Config) (aws.CredentialsProvider, error) {
	cfg := NewAwsConfig(config.Region, config.STSRegionalEndpoints)

	p := &AssumeRoleWithWebIdentityProvider{
		StsClient:               sts.NewFromConfig(cfg),
		RoleARN:                 config.RoleARN,
		RoleSessionName:         config.RoleSessionName,
		WebIdentityTokenFile:    config.WebIdentityTokenFile,
		WebIdentityTokenProcess: config.WebIdentityTokenProcess,
		Duration:                config.AssumeRoleDuration,
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
func NewSSORoleCredentialsProvider(k keyring.Keyring, config *Config) (aws.CredentialsProvider, error) {
	cfg := NewAwsConfig(config.SSORegion, config.STSRegionalEndpoints)

	ssoRoleCredentialsProvider := &SSORoleCredentialsProvider{
		OIDCClient: ssooidc.NewFromConfig(cfg),
		StartURL:   config.SSOStartURL,
		SSOClient:  sso.NewFromConfig(cfg),
		AccountID:  config.SSOAccountID,
		RoleName:   config.SSORoleName,
		UseStdout:  config.SSOUseStdout,
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

func (t *tempCredsCreator) provider(config *Config) (aws.CredentialsProvider, error) {
	var sourcecredsProvider aws.CredentialsProvider

	hasStoredCredentials, err := t.keyring.Has(config.ProfileName)
	if err != nil {
		return nil, err
	}

	if hasStoredCredentials && config.HasSourceProfile() {
		return nil, fmt.Errorf("profile %s: have stored credentials but source_profile is defined", config.ProfileName)
	} else if hasStoredCredentials {
		log.Printf("profile %s: using stored credentials", config.ProfileName)
		sourcecredsProvider = NewMasterCredentialsProvider(t.keyring, config.ProfileName)
	} else if config.HasSourceProfile() {
		sourcecredsProvider, err = t.provider(config.SourceProfile)
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
				return sourcecredsProvider, nil
			}
		}

		t.chainedMfa = config.MfaSerial
		log.Printf("profile %s: using GetSessionToken %s", config.ProfileName, mfaDetails(false, config))
		sourcecredsProvider, err = NewSessionTokenProvider(sourcecredsProvider, t.keyring.Keyring, config)
		if !config.HasRole() || err != nil {
			return sourcecredsProvider, err
		}
	}

	isMfaChained := config.MfaSerial != "" && config.MfaSerial == t.chainedMfa
	if isMfaChained {
		config.MfaSerial = ""
	}

	log.Printf("profile %s: using AssumeRole %s", config.ProfileName, mfaDetails(isMfaChained, config))
	return NewAssumeRoleProvider(sourcecredsProvider, t.keyring.Keyring, config)
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
func NewTempCredentialsProvider(config *Config, keyring *CredentialKeyring) (aws.CredentialsProvider, error) {
	t := tempCredsCreator{
		keyring: keyring,
	}
	return t.provider(config)
}

func NewFederationTokenCredentialsProvider(profileName string, k *CredentialKeyring, config *Config) (aws.CredentialsProvider, error) {
	credentialsName, err := FindMasterCredentialsNameFor(profileName, k, config)
	if err != nil {
		return nil, err
	}

	masterCreds := NewMasterCredentialsProvider(k, credentialsName)
	cfg := NewAwsConfigWithCredsProvider(masterCreds, config.Region, config.STSRegionalEndpoints)

	currentUsername, err := GetUsernameFromSession(cfg)
	if err != nil {
		return nil, err
	}

	log.Printf("Using GetFederationToken for credentials")
	return &FederationTokenProvider{
		StsClient: sts.NewFromConfig(cfg),
		Name:      currentUsername,
		Duration:  config.GetFederationTokenDuration,
	}, nil
}

func NewEnvironmentCredentialsProvider() (aws.CredentialsProvider, error) {
	return &EnvironmentVariablesCredentialsProvider{
		env: &environmentVariablesProviderImpl{},
	}, nil
}

func FindMasterCredentialsNameFor(profileName string, keyring *CredentialKeyring, config *Config) (string, error) {
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

	return FindMasterCredentialsNameFor(config.SourceProfileName, keyring, config)
}
