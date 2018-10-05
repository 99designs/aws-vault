package vault

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/99designs/aws-vault/prompt"
	"github.com/99designs/keyring"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
)

const (
	MaxSessionDuration    = time.Hour * 36
	MinSessionDuration    = time.Minute * 15
	MinAssumeRoleDuration = time.Minute * 15
	MaxAssumeRoleDuration = time.Hour * 12

	DefaultSessionDuration    = time.Hour * 4
	DefaultAssumeRoleDuration = time.Minute * 15
)

type VaultOptions struct {
	SessionDuration    time.Duration
	AssumeRoleDuration time.Duration
	ExpiryWindow       time.Duration
	MfaToken           string
	MfaPrompt          prompt.PromptFunc
	NoSession          bool
	Config             *Config
	MasterCreds        *credentials.Value
	Region             string
}

func (o VaultOptions) Validate() error {
	if o.SessionDuration < MinSessionDuration {
		return errors.New("Minimum session duration is " + MinSessionDuration.String())
	} else if o.SessionDuration > MaxSessionDuration {
		return errors.New("Maximum session duration is " + MaxSessionDuration.String())
	}
	if o.AssumeRoleDuration < MinAssumeRoleDuration {
		return errors.New("Minimum duration for assumed roles is " + MinAssumeRoleDuration.String())
	} else if o.AssumeRoleDuration > MaxAssumeRoleDuration {
		return errors.New("Maximum duration for assumed roles is " + MaxAssumeRoleDuration.String())
	}

	return nil
}

func (o VaultOptions) ApplyDefaults() VaultOptions {
	if o.AssumeRoleDuration == 0 {
		o.AssumeRoleDuration = DefaultAssumeRoleDuration
	}
	if o.SessionDuration == 0 {
		o.SessionDuration = DefaultSessionDuration
	}
	return o
}

type VaultProvider struct {
	credentials.Expiry
	VaultOptions
	profile  string
	expires  time.Time
	keyring  keyring.Keyring
	sessions *KeyringSessions
	config   *Config
	creds    map[string]credentials.Value
}

func NewVaultProvider(k keyring.Keyring, profile string, opts VaultOptions) (*VaultProvider, error) {
	opts = opts.ApplyDefaults()
	if err := opts.Validate(); err != nil {
		return nil, err
	}
	return &VaultProvider{
		VaultOptions: opts,
		keyring:      k,
		sessions:     &KeyringSessions{k, opts.Config},
		profile:      profile,
		config:       opts.Config,
		creds:        map[string]credentials.Value{},
	}, nil
}

// Retrieve returns credentials protected by a GetSessionToken. If there is an associated
// role in the profile then AssumeRole is applied. The benefit of a session is that it doesn't
// require MFA or a user prompt to access the keychain item, much like sudo.
func (p *VaultProvider) Retrieve() (credentials.Value, error) {
	if p.NoSession {
		return p.RetrieveWithoutSessionToken()
	}

	// sessions get stored by profile, not the source
	session, err := p.sessions.Retrieve(p.profile)
	if err != nil {
		if err == keyring.ErrKeyNotFound {
			log.Printf("Session not found in keyring for %s", p.profile)
		} else {
			log.Println(err)
		}

		// session lookup missed, we need to create a new one
		creds, err := p.getMasterCreds()
		if err != nil {
			return credentials.Value{}, err
		}

		session, err = p.getSessionToken(&creds)
		if err != nil {
			return credentials.Value{}, err
		}

		if err = p.sessions.Store(p.profile, session, time.Now().Add(p.SessionDuration)); err != nil {
			return credentials.Value{}, err
		}
	}

	log.Printf("Using session ****************%s, expires in %s",
		(*session.AccessKeyId)[len(*session.AccessKeyId)-4:],
		session.Expiration.Sub(time.Now()).String())

	if profile, exists := p.config.Profile(p.profile); exists && profile.RoleARN != "" {
		session, err = p.assumeRoleFromSession(session, profile)
		if err != nil {
			return credentials.Value{}, err
		}

		log.Printf("Using role ****************%s (from session token), expires in %s",
			(*session.AccessKeyId)[len(*session.AccessKeyId)-4:],
			session.Expiration.Sub(time.Now()).String())
	}

	window := p.ExpiryWindow
	if window == 0 {
		window = time.Minute * 5
	}

	p.SetExpiration(*session.Expiration, window)
	p.expires = *session.Expiration

	value := credentials.Value{
		AccessKeyID:     *session.AccessKeyId,
		SecretAccessKey: *session.SecretAccessKey,
		SessionToken:    *session.SessionToken,
	}

	return value, nil
}

// RetrieveWithoutSessionToken returns credentials that are either the master credentials or
// a session created with AssumeRole. This allows for usecases where a token created with AssumeRole
// wouldn't work.
func (p *VaultProvider) RetrieveWithoutSessionToken() (credentials.Value, error) {
	log.Println("Skipping session token and using master credentials directly")

	creds, err := p.getMasterCreds()
	if err != nil {
		return credentials.Value{}, err
	}

	if profile, exists := p.config.Profile(p.profile); exists && profile.RoleARN != "" {
		session, err := p.assumeRole(creds, profile)
		if err != nil {
			return credentials.Value{}, err
		}

		log.Printf("Using role ****************%s, expires in %s",
			(*session.AccessKeyId)[len(*session.AccessKeyId)-4:],
			session.Expiration.Sub(time.Now()).String())

		window := p.ExpiryWindow
		if window == 0 {
			window = time.Minute * 5
		}

		p.SetExpiration(*session.Expiration, window)
		p.expires = *session.Expiration

		value := credentials.Value{
			AccessKeyID:     *session.AccessKeyId,
			SecretAccessKey: *session.SecretAccessKey,
			SessionToken:    *session.SessionToken,
		}

		return value, nil
	}

	// no role, exposes master credentials which don't expire
	return creds, nil
}

func (p *VaultProvider) HasRole() bool {
	profile, exists := p.config.Profile(p.profile)
	return exists && profile.RoleARN != ""
}

func (p *VaultProvider) HasMfa() bool {
	profile, exists := p.Config.Profile(p.profile)
	return exists && profile.MFASerial != ""
}

func (p VaultProvider) awsConfig() *aws.Config {
	if region := os.Getenv("AWS_REGION"); region != "" {
		log.Printf("Using region %q from AWS_REGION", region)
		return aws.NewConfig().WithRegion(region)
	}

	if region := os.Getenv("AWS_DEFAULT_REGION"); region != "" {
		log.Printf("Using region %q from AWS_DEFAULT_REGION", region)
		return aws.NewConfig().WithRegion(region)
	}

	if profile, ok := p.Config.Profile(p.profile); ok {
		if profile.Region != "" {
			log.Printf("Using region %q from profile", profile.Region)
			return aws.NewConfig().WithRegion(profile.Region)
		}
	}

	return aws.NewConfig()
}

func (p *VaultProvider) getMasterCreds() (credentials.Value, error) {
	if p.MasterCreds != nil {
		return *p.MasterCreds, nil
	}

	source, _ := p.Config.SourceProfile(p.profile)

	val, ok := p.creds[source.Name]
	if !ok {
		creds := credentials.NewCredentials(&KeyringProvider{Keyring: p.keyring, Profile: source.Name})

		var err error
		if val, err = creds.Get(); err != nil {
			log.Printf("Failed to find credentials for profile %q in keyring", source.Name)
			return val, err
		}

		p.creds[source.Name] = val
	}

	return val, nil
}

func (p *VaultProvider) getSessionToken(creds *credentials.Value) (sts.Credentials, error) {
	params := &sts.GetSessionTokenInput{
		DurationSeconds: aws.Int64(int64(p.SessionDuration.Seconds())),
	}

	if profile, _ := p.Config.Profile(p.profile); profile.MFASerial != "" {
		params.SerialNumber = aws.String(profile.MFASerial)
		if p.MfaToken == "" {
			token, err := p.MfaPrompt(fmt.Sprintf("Enter token for %s: ", profile.MFASerial))
			if err != nil {
				return sts.Credentials{}, err
			}
			params.TokenCode = aws.String(token)
		} else {
			params.TokenCode = aws.String(p.MfaToken)
		}
	}

	client := sts.New(session.New(p.awsConfig().
		WithCredentials(credentials.NewCredentials(&credentials.StaticProvider{
			Value: *creds,
		}))))

	source, _ := p.Config.SourceProfile(p.profile)
	log.Printf("Getting new session token for profile %s", source.Name)

	resp, err := client.GetSessionToken(params)
	if err != nil {
		return sts.Credentials{}, err
	}

	return *resp.Credentials, nil
}

func (p *VaultProvider) roleSessionName() string {
	if profile, _ := p.Config.Profile(p.profile); profile.RoleSessionName != "" {
		return profile.RoleSessionName
	}

	// Try to work out a role name that will hopefully end up unique.
	return fmt.Sprintf("%d", time.Now().UTC().UnixNano())
}

// assumeRoleFromSession takes a session created with GetSessionToken and uses that to assume a role
func (p *VaultProvider) assumeRoleFromSession(creds sts.Credentials, profile Profile) (sts.Credentials, error) {
	client := sts.New(session.New(p.awsConfig().
		WithCredentials(credentials.NewStaticCredentials(
			*creds.AccessKeyId,
			*creds.SecretAccessKey,
			*creds.SessionToken,
		))))

	input := &sts.AssumeRoleInput{
		RoleArn:         aws.String(profile.RoleARN),
		RoleSessionName: aws.String(p.roleSessionName()),
		DurationSeconds: aws.Int64(int64(p.AssumeRoleDuration.Seconds())),
	}

	if profile.ExternalID != "" {
		input.ExternalId = aws.String(profile.ExternalID)
	}

	log.Printf("Assuming role %s from session token", profile.RoleARN)
	resp, err := client.AssumeRole(input)
	if err != nil {
		return sts.Credentials{}, err
	}

	return *resp.Credentials, nil
}

// assumeRole uses IAM credentials to assume a role
func (p *VaultProvider) assumeRole(creds credentials.Value, profile Profile) (sts.Credentials, error) {
	client := sts.New(session.New(p.awsConfig().
		WithCredentials(credentials.NewCredentials(&credentials.StaticProvider{Value: creds})),
	))

	input := &sts.AssumeRoleInput{
		RoleArn:         aws.String(profile.RoleARN),
		RoleSessionName: aws.String(p.roleSessionName()),
		DurationSeconds: aws.Int64(int64(p.AssumeRoleDuration.Seconds())),
	}

	if profile.ExternalID != "" {
		input.ExternalId = aws.String(profile.ExternalID)
	}

	// if we don't have a session, we need to include MFA token in the AssumeRole call
	if profile.MFASerial != "" {
		input.SerialNumber = aws.String(profile.MFASerial)
		if p.MfaToken == "" {
			token, err := p.MfaPrompt(fmt.Sprintf("Enter token for %s: ", profile.MFASerial))
			if err != nil {
				return sts.Credentials{}, err
			}
			input.TokenCode = aws.String(token)
		} else {
			input.TokenCode = aws.String(p.MfaToken)
		}
	}

	log.Printf("Assuming role %s with iam credentials", profile.RoleARN)
	resp, err := client.AssumeRole(input)
	if err != nil {
		return sts.Credentials{}, err
	}

	return *resp.Credentials, nil
}

type KeyringProvider struct {
	Keyring keyring.Keyring
	Profile string
	Region  string
}

func (p *KeyringProvider) IsExpired() bool {
	return false
}

func (p *KeyringProvider) Retrieve() (val credentials.Value, err error) {
	log.Printf("Looking up keyring for %s", p.Profile)
	item, err := p.Keyring.Get(p.Profile)
	if err != nil {
		log.Println("Error from keyring", err)
		return val, err
	}
	if err = json.Unmarshal(item.Data, &val); err != nil {
		return val, fmt.Errorf("Invalid data in keyring: %v", err)
	}
	return val, err
}

func (p *KeyringProvider) Store(val credentials.Value) error {
	bytes, err := json.Marshal(val)
	if err != nil {
		return err
	}

	return p.Keyring.Set(keyring.Item{
		Key:   p.Profile,
		Label: fmt.Sprintf("aws-vault (%s)", p.Profile),
		Data:  bytes,
	})
}

func (p *KeyringProvider) Delete() error {
	return p.Keyring.Remove(p.Profile)
}

type VaultCredentials struct {
	*credentials.Credentials
	provider *VaultProvider
}

func NewVaultCredentials(k keyring.Keyring, profile string, opts VaultOptions) (*VaultCredentials, error) {
	provider, err := NewVaultProvider(k, profile, opts)
	if err != nil {
		return nil, err
	}

	return &VaultCredentials{credentials.NewCredentials(provider), provider}, nil
}

func (v *VaultCredentials) Expires() time.Time {
	return v.provider.expires
}
