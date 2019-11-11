package vault

import (
	"fmt"
	"log"
	"time"

	"github.com/99designs/keyring"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
)

const DefaultExpirationWindow = 5 * time.Minute

type VaultProvider struct {
	credentials.Expiry
	expires     time.Time
	keyring     keyring.Keyring
	sessions    *KeyringSessions
	config      *Config
	creds       map[string]credentials.Value
	MasterCreds *credentials.Value
}

func NewVaultProvider(k keyring.Keyring, profileName string, opts *Config) (*VaultProvider, error) {
	if err := opts.Validate(); err != nil {
		return nil, err
	}
	return &VaultProvider{
		config:   opts,
		keyring:  k,
		sessions: &KeyringSessions{k},
		creds:    map[string]credentials.Value{},
	}, nil
}

// Retrieve returns credentials protected by a GetSessionToken. If there is an associated
// role in the profile then AssumeRole is applied. The benefit of a session is that it doesn't
// require MFA or a user prompt to access the keychain item, much like sudo.
func (p *VaultProvider) Retrieve() (credentials.Value, error) {
	if p.config.NoSession {
		return p.RetrieveWithoutSessionToken()
	}

	// sessions get stored by profile, not the source
	session, err := p.sessions.Retrieve(p.config.CredentialName, p.config.MfaSerial)
	if err != nil {
		if err == keyring.ErrKeyNotFound {
			log.Printf("Session not found in keyring for %s", p.config.CredentialName)
		} else {
			log.Println(err)
		}

		// session lookup missed, we need to create a new one.
		// If the selected profile has a RoleARN, create a new VaultCredentials for the source
		// to support using an existing session for master credentials and allow assume role chaining.
		if p.config.RoleARN != "" {
			creds, err := NewVaultCredentials(p.keyring, p.config.CredentialName, p.config)
			if err != nil {
				log.Printf("Failed to create NewVaultCredentials for profile %q", p.config.CredentialName)
				return credentials.Value{}, err
			}
			val, err := creds.Get()
			if err != nil {
				return credentials.Value{}, err
			}
			exp := creds.Expires()
			session = sts.Credentials{
				AccessKeyId:     &val.AccessKeyID,
				SecretAccessKey: &val.SecretAccessKey,
				SessionToken:    &val.SessionToken,
				Expiration:      &exp,
			}
		} else {
			creds, err := p.getMasterCreds()
			if err != nil {
				return credentials.Value{}, err
			}
			session, err = p.getSessionToken(&creds)
			if err != nil {
				return credentials.Value{}, err
			}

			if err = p.sessions.Store(p.config.CredentialName, p.config.MfaSerial, session); err != nil {
				return credentials.Value{}, err
			}
		}
	}

	log.Printf("Using session ****************%s, expires in %s",
		(*session.AccessKeyId)[len(*session.AccessKeyId)-4:],
		session.Expiration.Sub(time.Now()).String())

	if p.config.RoleARN != "" {
		session, err = p.assumeRoleFromSession(session, p.config)
		if err != nil {
			return credentials.Value{}, err
		}

		log.Printf("Using role ****************%s (from session token), expires in %s",
			(*session.AccessKeyId)[len(*session.AccessKeyId)-4:],
			session.Expiration.Sub(time.Now()).String())
	}

	p.SetExpiration(*session.Expiration, DefaultExpirationWindow)
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

	if p.config.RoleARN != "" {
		session, err := p.assumeRole(creds, p.config)
		if err != nil {
			return credentials.Value{}, err
		}

		log.Printf("Using role ****************%s, expires in %s",
			(*session.AccessKeyId)[len(*session.AccessKeyId)-4:],
			session.Expiration.Sub(time.Now()).String())

		p.SetExpiration(*session.Expiration, DefaultExpirationWindow)
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

func (p *VaultProvider) getMasterCreds() (credentials.Value, error) {
	if p.MasterCreds != nil {
		return *p.MasterCreds, nil
	}

	val, ok := p.creds[p.config.CredentialName]
	if !ok {
		creds := credentials.NewCredentials(&KeyringProvider{Keyring: p.keyring, CredentialName: p.config.CredentialName})

		var err error
		if val, err = creds.Get(); err != nil {
			log.Printf("Failed to find credentials for profile %q in keyring", p.config.CredentialName)
			return val, err
		}

		p.creds[p.config.CredentialName] = val
	}

	return val, nil
}

func (p *VaultProvider) getSessionToken(creds *credentials.Value) (sts.Credentials, error) {
	params := &sts.GetSessionTokenInput{
		DurationSeconds: aws.Int64(int64(p.config.SessionDuration.Seconds())),
	}

	if p.config.MfaSerial != "" {
		params.SerialNumber = aws.String(p.config.MfaSerial)
		if p.config.MfaToken == "" {
			token, err := p.config.MfaPrompt(fmt.Sprintf("Enter token for %s: ", p.config.MfaSerial))
			if err != nil {
				return sts.Credentials{}, err
			}
			params.TokenCode = aws.String(token)
		} else {
			params.TokenCode = aws.String(p.config.MfaToken)
		}
	}

	client := sts.New(
		session.New(
			aws.NewConfig().WithCredentials(
				credentials.NewCredentials(&credentials.StaticProvider{Value: *creds}),
			)))

	log.Printf("Getting new session token for profile %s", p.config.CredentialName)

	resp, err := client.GetSessionToken(params)
	if err != nil {
		return sts.Credentials{}, err
	}

	return *resp.Credentials, nil
}

func (p *VaultProvider) roleSessionName() string {
	if p.config.RoleSessionName != "" {
		return p.config.RoleSessionName
	}

	// Try to work out a role name that will hopefully end up unique.
	return fmt.Sprintf("%d", time.Now().UTC().UnixNano())
}

// assumeRoleFromSession takes a session created with GetSessionToken and uses that to assume a role
func (p *VaultProvider) assumeRoleFromSession(creds sts.Credentials, config *Config) (sts.Credentials, error) {
	client := sts.New(session.New(aws.NewConfig().
		WithCredentials(credentials.NewStaticCredentials(
			*creds.AccessKeyId,
			*creds.SecretAccessKey,
			*creds.SessionToken,
		))))

	input := &sts.AssumeRoleInput{
		RoleArn:         aws.String(config.RoleARN),
		RoleSessionName: aws.String(p.roleSessionName()),
		DurationSeconds: aws.Int64(int64(p.config.AssumeRoleDuration.Seconds())),
	}

	if config.ExternalID != "" {
		input.ExternalId = aws.String(config.ExternalID)
	}

	log.Printf("Assuming role %s from session token", config.RoleARN)
	resp, err := client.AssumeRole(input)
	if err != nil {
		return sts.Credentials{}, err
	}

	return *resp.Credentials, nil
}

// assumeRole uses IAM credentials to assume a role
func (p *VaultProvider) assumeRole(creds credentials.Value, config *Config) (sts.Credentials, error) {
	client := sts.New(
		session.New(
			aws.NewConfig().WithCredentials(
				credentials.NewCredentials(&credentials.StaticProvider{Value: creds}))))

	input := &sts.AssumeRoleInput{
		RoleArn:         aws.String(config.RoleARN),
		RoleSessionName: aws.String(p.roleSessionName()),
		DurationSeconds: aws.Int64(int64(p.config.AssumeRoleDuration.Seconds())),
	}

	if config.ExternalID != "" {
		input.ExternalId = aws.String(config.ExternalID)
	}

	// if we don't have a session, we need to include MFA token in the AssumeRole call
	if p.config.MfaSerial != "" {
		input.SerialNumber = aws.String(p.config.MfaSerial)
		if p.config.MfaToken == "" {
			token, err := p.config.MfaPrompt(fmt.Sprintf("Enter token for %s: ", p.config.MfaSerial))
			if err != nil {
				return sts.Credentials{}, err
			}
			input.TokenCode = aws.String(token)
		} else {
			input.TokenCode = aws.String(p.config.MfaToken)
		}
	}

	log.Printf("Assuming role %s with iam credentials", config.RoleARN)
	resp, err := client.AssumeRole(input)
	if err != nil {
		return sts.Credentials{}, err
	}

	return *resp.Credentials, nil
}

type VaultCredentials struct {
	*credentials.Credentials
	provider *VaultProvider
}

func NewVaultCredentials(k keyring.Keyring, profileName string, opts *Config) (*VaultCredentials, error) {
	provider, err := NewVaultProvider(k, profileName, opts)
	if err != nil {
		return nil, err
	}

	return &VaultCredentials{credentials.NewCredentials(provider), provider}, nil
}

func (v *VaultCredentials) Expires() time.Time {
	return v.provider.expires
}
