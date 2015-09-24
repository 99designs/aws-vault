package main

import (
	"fmt"
	"log"
	"time"

	"github.com/99designs/aws-vault/keyring"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/service/sts"
)

type stsClient interface {
	AssumeRole(input *sts.AssumeRoleInput) (*sts.AssumeRoleOutput, error)
	GetSessionToken(input *sts.GetSessionTokenInput) (*sts.GetSessionTokenOutput, error)
}

type VaultProvider struct {
	credentials.Expiry
	Keyring         keyring.Keyring
	Profile         string
	SessionDuration time.Duration
	ExpiryWindow    time.Duration
	sessionStore    *sessionStore
	profilesConf    profiles
	session         *sts.Credentials
	client          stsClient
}

func NewVaultProvider(k keyring.Keyring, profile string, d time.Duration) (*VaultProvider, error) {
	conf, err := parseProfiles()
	if err != nil {
		return nil, err
	}
	return &VaultProvider{
		Keyring:         k,
		Profile:         profile,
		SessionDuration: d,
		ExpiryWindow:    time.Second * 90,
		profilesConf:    conf,
		sessionStore:    defaultSessionStore,
	}, nil
}

func (p *VaultProvider) credentials() (credentials.Value, error) {
	profile := p.profilesConf.sourceProfile(p.Profile)
	creds := credentials.NewChainCredentials([]credentials.Provider{
		&credentials.EnvProvider{},
		&credentials.SharedCredentialsProvider{Filename: "", Profile: profile},
		&KeyringProvider{Keyring: p.Keyring, Profile: profile},
	})

	return creds.Get()
}

func (p *VaultProvider) sessionKey() (sessionKey, error) {
	creds, err := p.credentials()
	if err != nil {
		return sessionKey{}, err
	}

	return sessionKey{creds, p.Profile, p.profilesConf[p.Profile]["mfa_serial"]}, nil
}

func (p *VaultProvider) Retrieve() (credentials.Value, error) {
	key, err := p.sessionKey()
	if err != nil {
		return credentials.Value{}, err
	}

	session, err := p.sessionStore.Get(key)
	if err == errSessionNotFound {
		session, err = p.getSessionToken(key.Value)
		if err != nil {
			return credentials.Value{}, err
		}

		if role, ok := p.profilesConf[p.Profile]["role_arn"]; ok {
			session, err = p.assumeRole(session, role)
			if err != nil {
				return credentials.Value{}, err
			}
		}

		p.sessionStore.Set(key, session)
	} else if err != nil {
		return credentials.Value{}, err
	}

	log.Printf("Session token expires in %s", session.Expiration.Sub(time.Now()))
	p.SetExpiration(*session.Expiration, p.ExpiryWindow)

	value := credentials.Value{
		AccessKeyID:     *session.AccessKeyId,
		SecretAccessKey: *session.SecretAccessKey,
		SessionToken:    *session.SessionToken,
	}

	return value, nil
}

func (p *VaultProvider) getSessionToken(creds credentials.Value) (sts.Credentials, error) {
	params := &sts.GetSessionTokenInput{
		DurationSeconds: aws.Int64(int64(p.SessionDuration.Seconds())),
	}

	if mfa, ok := p.profilesConf[p.Profile]["mfa_serial"]; ok {
		token, err := promptPassword(fmt.Sprintf("Enter token for %s: ", mfa))
		if err != nil {
			return sts.Credentials{}, err
		}
		params.SerialNumber = aws.String(mfa)
		params.TokenCode = aws.String(token)
	}

	client := p.client
	if client == nil {
		client = sts.New(&aws.Config{Credentials: credentials.NewStaticCredentials(
			creds.AccessKeyID,
			creds.SecretAccessKey,
			"",
		)})
	}

	log.Printf("Getting new session token for profile %s", p.Profile)
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
		DurationSeconds: aws.Int64(int64(p.SessionDuration.Seconds())),
	}

	log.Printf("Assuming role %s", roleArn)
	resp, err := client.AssumeRole(input)
	if err != nil {
		return sts.Credentials{}, err
	}

	return *resp.Credentials, nil
}

type KeyringProvider struct {
	Keyring      keyring.Keyring
	SessionStore *sessionStore
	Profile      string
}

func (p *KeyringProvider) IsExpired() bool {
	return false
}

func (p *KeyringProvider) Retrieve() (val credentials.Value, err error) {
	log.Printf("Looking up keyring for %s", p.Profile)
	if err = keyring.Unmarshal(p.Keyring, p.Profile, &val); err != nil {
		log.Println("Error looking up keyring", err)
	}
	return
}

func (p *KeyringProvider) Store(val credentials.Value) error {
	return keyring.Marshal(p.Keyring, p.Profile, val)
}

func (p *KeyringProvider) Delete() error {
	return p.Keyring.Remove(p.Profile)
}
