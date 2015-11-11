package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/99designs/aws-vault/keyring"
	"github.com/99designs/aws-vault/prompt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/service/sts"
)

const (
	MaxSessionDuration    = time.Hour * 36
	MinSessionDuration    = time.Minute * 15
	MinAssumeRoleDuration = time.Minute * 15
	MaxAssumeRoleDuration = time.Hour

	DefaultSessionDuration    = time.Hour * 4
	DefaultAssumeRoleDuration = time.Minute * 15
)

type stsClient interface {
	AssumeRole(input *sts.AssumeRoleInput) (*sts.AssumeRoleOutput, error)
	GetSessionToken(input *sts.GetSessionTokenInput) (*sts.GetSessionTokenOutput, error)
}

type VaultOptions struct {
	SessionDuration    time.Duration
	AssumeRoleDuration time.Duration
	ExpiryWindow       time.Duration
	MfaToken           string
	MfaPrompt          prompt.PromptFunc
}

func (o VaultOptions) Validate() error {
	if o.SessionDuration < MinSessionDuration {
		return errors.New("Minimum session duration is " + MinSessionDuration.String())
	} else if o.SessionDuration > MaxSessionDuration {
		return errors.New("Maximum session duration is " + MaxSessionDuration.String())
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
	profiles profiles
	client   stsClient
	creds    map[string]credentials.Value
}

func NewVaultProvider(k keyring.Keyring, profile string, opts VaultOptions) (*VaultProvider, error) {
	opts = opts.ApplyDefaults()
	if err := opts.Validate(); err != nil {
		return nil, err
	}
	profiles, err := parseProfiles()
	if err != nil {
		return nil, err
	}
	return &VaultProvider{
		VaultOptions: opts,
		keyring:      k,
		sessions:     &KeyringSessions{k, profiles},
		profile:      profile,
		profiles:     profiles,
		creds:        map[string]credentials.Value{},
	}, nil
}

func (p *VaultProvider) Retrieve() (credentials.Value, error) {
	creds, err := p.getMasterCreds()
	if err != nil {
		return credentials.Value{}, err
	}

	session, err := p.sessions.Retrieve(p.profile, p.SessionDuration)
	if err != nil {
		if err == keyring.ErrKeyNotFound {
			log.Println("Session not found in keyring")
		} else {
			log.Println(err)
		}

		session, err = p.getSessionToken(&creds)
		if err != nil {
			return credentials.Value{}, err
		}

		if err = p.sessions.Store(p.profile, session, p.SessionDuration); err != nil {
			return credentials.Value{}, err
		}
	}

	log.Printf("Using session ****************%s, expires in %s",
		(*session.AccessKeyId)[len(*session.AccessKeyId)-4:],
		session.Expiration.Sub(time.Now()).String())

	window := p.ExpiryWindow
	if window == 0 {
		window = time.Minute * 5
	}

	if role, ok := p.profiles[p.profile]["role_arn"]; ok {
		session, err = p.assumeRole(session, role)
		if err != nil {
			return credentials.Value{}, err
		}

		log.Printf("Using role ****************%s, expires in %s",
			(*session.AccessKeyId)[len(*session.AccessKeyId)-4:],
			session.Expiration.Sub(time.Now()).String())
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

func (p *VaultProvider) getMasterCreds() (credentials.Value, error) {
	source := p.profiles.sourceProfile(p.profile)

	creds, ok := p.creds[source]
	if !ok {
		provider := credentials.NewChainCredentials([]credentials.Provider{
			&credentials.EnvProvider{},
			&credentials.SharedCredentialsProvider{Filename: "", Profile: p.profile},
			&KeyringProvider{Keyring: p.keyring, Profile: source},
		})

		var err error
		if creds, err = provider.Get(); err != nil {
			return creds, err
		}

		p.creds[source] = creds
	}

	return creds, nil
}

func (p *VaultProvider) getSessionToken(creds *credentials.Value) (sts.Credentials, error) {
	params := &sts.GetSessionTokenInput{
		DurationSeconds: aws.Int64(int64(p.SessionDuration.Seconds())),
	}

	log.Printf("%#v", p)

	if mfa, ok := p.profiles[p.profile]["mfa_serial"]; ok {
		params.SerialNumber = aws.String(mfa)
		if p.MfaToken == "" {
			token, err := p.MfaPrompt(fmt.Sprintf("Enter token for %s: ", mfa))
			if err != nil {
				return sts.Credentials{}, err
			}
			params.TokenCode = aws.String(token)
		} else {
			params.TokenCode = aws.String(p.MfaToken)
		}
	}

	client := p.client
	if client == nil {
		client = sts.New(&aws.Config{
			Credentials: credentials.NewCredentials(&credentials.StaticProvider{
				Value: *creds,
			}),
		})
	}

	log.Printf("Getting new session token for profile %s", p.profiles.sourceProfile(p.profile))
	resp, err := client.GetSessionToken(params)
	if err != nil {
		return sts.Credentials{}, err
	}

	return *resp.Credentials, nil
}

func (p *VaultProvider) assumeRole(session sts.Credentials, roleArn string) (sts.Credentials, error) {
	client := p.client
	if client == nil {
		client = sts.New(&aws.Config{Credentials: credentials.NewStaticCredentials(
			*session.AccessKeyId,
			*session.SecretAccessKey,
			*session.SessionToken,
		)})
	}

	// Try to work out a role name that will hopefully end up unique.
	roleSessionName := fmt.Sprintf("%d", time.Now().UTC().UnixNano())

	input := &sts.AssumeRoleInput{
		RoleArn:         aws.String(roleArn),
		RoleSessionName: aws.String(roleSessionName),
		DurationSeconds: aws.Int64(int64(p.AssumeRoleDuration.Seconds())),
	}

	log.Printf("Assuming role %s", roleArn)
	resp, err := client.AssumeRole(input)
	if err != nil {
		return sts.Credentials{}, err
	}

	return *resp.Credentials, nil
}

type KeyringProvider struct {
	Keyring keyring.Keyring
	Profile string
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

	err = json.Unmarshal(item.Data, &val)
	return
}

func (p *KeyringProvider) Store(val credentials.Value) error {
	bytes, err := json.Marshal(val)
	if err != nil {
		return err
	}

	return p.Keyring.Set(keyring.Item{
		Key:  p.Profile,
		Data: bytes,
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
