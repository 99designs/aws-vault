package vault

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

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
		Region:                      region,
		EndpointResolverWithOptions: getSTSEndpointResolver(stsRegionalEndpoints),
	}
}

func NewAwsConfigWithCredsProvider(credsProvider aws.CredentialsProvider, region, stsRegionalEndpoints string) aws.Config {
	return aws.Config{
		Region:                      region,
		Credentials:                 credsProvider,
		EndpointResolverWithOptions: getSTSEndpointResolver(stsRegionalEndpoints),
	}
}

func FormatKeyForDisplay(k string) string {
	return fmt.Sprintf("****************%s", k[len(k)-4:])
}

// NewMasterCredentialsProvider creates a provider for the master credentials
func NewMasterCredentialsProvider(k *CredentialKeyring, credentialsName string) *KeyringProvider {
	return &KeyringProvider{k, credentialsName}
}

func NewSessionTokenProvider(credsProvider aws.CredentialsProvider, k keyring.Keyring, config *ProfileConfig) (aws.CredentialsProvider, error) {
	cfg := NewAwsConfigWithCredsProvider(credsProvider, config.Region, config.STSRegionalEndpoints)

	sessionTokenProvider := &SessionTokenProvider{
		StsClient: sts.NewFromConfig(cfg),
		Duration:  config.GetSessionTokenDuration(),
		Mfa:       NewMfa(config),
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
func NewAssumeRoleProvider(credsProvider aws.CredentialsProvider, k keyring.Keyring, config *ProfileConfig) (aws.CredentialsProvider, error) {
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
		Mfa:               NewMfa(config),
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
func NewAssumeRoleWithWebIdentityProvider(k keyring.Keyring, config *ProfileConfig) (aws.CredentialsProvider, error) {
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
func NewSSORoleCredentialsProvider(k keyring.Keyring, config *ProfileConfig) (aws.CredentialsProvider, error) {
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

// NewCredentialProcessProvider creates a provider to retrieve credentials from an external
// executable as described in https://docs.aws.amazon.com/cli/latest/topic/config-vars.html#sourcing-credentials-from-external-processes
func NewCredentialProcessProvider(k keyring.Keyring, config *ProfileConfig) (aws.CredentialsProvider, error) {
	credentialProcessProvider := &CredentialProcessProvider{
		CredentialProcess: config.CredentialProcess,
	}

	if UseSessionCache {
		return &CachedSessionProvider{
			SessionKey: SessionMetadata{
				Type:        "credential_process",
				ProfileName: config.ProfileName,
			},
			Keyring:         &SessionKeyring{Keyring: k},
			ExpiryWindow:    defaultExpirationWindow,
			CredentialsFunc: credentialProcessProvider.callCredentialProcess,
		}, nil
	}

	return credentialProcessProvider, nil
}

func NewFederationTokenCredentialsProvider(ctx context.Context, profileName string, k *CredentialKeyring, config *ProfileConfig) (aws.CredentialsProvider, error) {
	credentialsName, err := FindMasterCredentialsNameFor(profileName, k, config)
	if err != nil {
		return nil, err
	}
	masterCreds := NewMasterCredentialsProvider(k, credentialsName)

	return NewFederationTokenProvider(ctx, masterCreds, config)
}

func NewFederationTokenProvider(ctx context.Context, credsProvider aws.CredentialsProvider, config *ProfileConfig) (*FederationTokenProvider, error) {
	cfg := NewAwsConfigWithCredsProvider(credsProvider, config.Region, config.STSRegionalEndpoints)

	currentUsername, err := GetUsernameFromSession(ctx, cfg)
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

func FindMasterCredentialsNameFor(profileName string, keyring *CredentialKeyring, config *ProfileConfig) (string, error) {
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

type tempCredsCreator struct {
	// DisableSessions will disable the use of GetSessionToken when set to true
	DisableSessions bool
	Keyring         *CredentialKeyring

	chainedMfa string
}

func (t *tempCredsCreator) getSourceCreds(config *ProfileConfig) (sourcecredsProvider aws.CredentialsProvider, err error) {
	if config.HasSourceProfile() {
		log.Printf("profile %s: sourcing credentials from profile %s", config.ProfileName, config.SourceProfile.ProfileName)
		return t.GetProviderForProfile(config.SourceProfile)
	}

	hasStoredCredentials, err := t.Keyring.Has(config.ProfileName)
	if err != nil {
		return nil, err
	}

	if hasStoredCredentials {
		log.Printf("profile %s: using stored credentials", config.ProfileName)
		return NewMasterCredentialsProvider(t.Keyring, config.ProfileName), nil
	}

	return nil, fmt.Errorf("profile %s: credentials missing", config.ProfileName)
}

func (t *tempCredsCreator) GetProviderForProfile(config *ProfileConfig) (aws.CredentialsProvider, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	if config.HasSSOStartURL() {
		log.Printf("profile %s: using SSO role credentials", config.ProfileName)
		return NewSSORoleCredentialsProvider(t.Keyring.Keyring, config)
	}

	if config.HasWebIdentity() {
		log.Printf("profile %s: using web identity", config.ProfileName)
		return NewAssumeRoleWithWebIdentityProvider(t.Keyring.Keyring, config)
	}

	if config.HasCredentialProcess() {
		log.Printf("profile %s: using credential process", config.ProfileName)
		return NewCredentialProcessProvider(t.Keyring.Keyring, config)
	}

	sourcecredsProvider, err := t.getSourceCreds(config)
	if err != nil {
		return nil, err
	}

	if config.HasRole() {
		isMfaChained := config.MfaSerial != "" && config.MfaSerial == t.chainedMfa
		if isMfaChained {
			config.MfaSerial = ""
		}
		log.Printf("profile %s: using AssumeRole %s", config.ProfileName, mfaDetails(isMfaChained, config))
		return NewAssumeRoleProvider(sourcecredsProvider, t.Keyring.Keyring, config)
	}

	canUseGetSessionToken, reason := t.canUseGetSessionToken(config)
	if canUseGetSessionToken {
		t.chainedMfa = config.MfaSerial
		log.Printf("profile %s: using GetSessionToken %s", config.ProfileName, mfaDetails(false, config))
		return NewSessionTokenProvider(sourcecredsProvider, t.Keyring.Keyring, config)
	}

	log.Printf("profile %s: skipping GetSessionToken because %s", config.ProfileName, reason)
	return sourcecredsProvider, nil
}

// canUseGetSessionToken determines if GetSessionToken should be used, and if not returns a reason
func (t *tempCredsCreator) canUseGetSessionToken(c *ProfileConfig) (bool, string) {
	if t.DisableSessions {
		return false, "sessions are disabled"
	}

	if c.IsChained() {
		if !c.ChainedFromProfile.HasMfaSerial() {
			return false, fmt.Sprintf("profile '%s' has no MFA serial defined", c.ChainedFromProfile.ProfileName)
		}

		if !c.HasMfaSerial() && c.ChainedFromProfile.HasMfaSerial() {
			return false, fmt.Sprintf("profile '%s' has no MFA serial defined", c.ProfileName)
		}

		if c.ChainedFromProfile.MfaSerial != c.MfaSerial {
			return false, fmt.Sprintf("MFA serial doesn't match profile '%s'", c.ChainedFromProfile.ProfileName)
		}

		if c.ChainedFromProfile.AssumeRoleDuration > roleChainingMaximumDuration {
			return false, fmt.Sprintf("duration %s in profile '%s' is greater than the AWS maximum %s for chaining MFA", c.ChainedFromProfile.AssumeRoleDuration, c.ChainedFromProfile.ProfileName, roleChainingMaximumDuration)
		}
	}

	return true, ""
}

func mfaDetails(mfaChained bool, config *ProfileConfig) string {
	if mfaChained {
		return "(chained MFA)"
	}
	if config.HasMfaSerial() {
		return "(with MFA)"
	}
	return ""
}

// NewTempCredentialsProvider creates a credential provider for the given config
func NewTempCredentialsProvider(config *ProfileConfig, keyring *CredentialKeyring, disableSessions bool) (aws.CredentialsProvider, error) {
	t := tempCredsCreator{
		Keyring:         keyring,
		DisableSessions: disableSessions,
	}
	return t.GetProviderForProfile(config)
}
