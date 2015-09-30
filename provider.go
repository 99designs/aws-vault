package main

import (
	"encoding/json"
	"errors"
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
	expires         time.Time
	Keyring         keyring.Keyring
	Profile         string
	SessionDuration time.Duration
	ExpiryWindow    time.Duration
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
	}, nil
}

func (p *VaultProvider) Retrieve() (credentials.Value, error) {
	session, err := p.getCachedSession()
	if err != nil {
		if err == keyring.ErrKeyNotFound {
			log.Println("Session not found in keyring")
		} else {
			log.Println(err)
		}

		session, err = p.getSessionToken(p.SessionDuration)
		if err != nil {
			return credentials.Value{}, err
		}

		if role, ok := p.profilesConf[p.Profile]["role_arn"]; ok {
			session, err = p.assumeRole(session, role)
			if err != nil {
				return credentials.Value{}, err
			}
		}

		bytes, err := json.Marshal(session)
		if err != nil {
			return credentials.Value{}, err
		}

		// store a session in the keyring
		p.Keyring.Set(keyring.Item{
			Key:  sessionKey(p.Profile),
			Data: bytes,
		})
	}

	log.Printf("Session token expires in %s", session.Expiration.Sub(time.Now()))
	p.SetExpiration(*session.Expiration, p.ExpiryWindow)
	p.expires = *session.Expiration

	value := credentials.Value{
		AccessKeyID:     *session.AccessKeyId,
		SecretAccessKey: *session.SecretAccessKey,
		SessionToken:    *session.SessionToken,
	}

	return value, nil
}

func sessionKey(profile string) string {
	return profile + " session"
}

func (p *VaultProvider) getCachedSession() (session sts.Credentials, err error) {
	item, err := p.Keyring.Get(sessionKey(p.Profile))
	if err != nil {
		return session, err
	}

	if err = json.Unmarshal(item.Data, &session); err != nil {
		return session, err
	}

	if session.Expiration.Before(time.Now()) {
		return session, errors.New("Session is expired")
	}

	return
}

func (p *VaultProvider) getSessionToken(length time.Duration) (sts.Credentials, error) {
	source := p.profilesConf.sourceProfile(p.Profile)

	params := &sts.GetSessionTokenInput{
		DurationSeconds: aws.Int64(int64(length.Seconds())),
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
		client = sts.New(&aws.Config{Credentials: credentials.NewChainCredentials(
			p.defaultProviders(source),
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

func (p *VaultProvider) defaultProviders(profile string) []credentials.Provider {
	return []credentials.Provider{
		&credentials.EnvProvider{},
		&credentials.SharedCredentialsProvider{Filename: "", Profile: profile},
		&KeyringProvider{Keyring: p.Keyring, Profile: profile},
	}
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
		return val, err
	}

	err = json.Unmarshal(item.Data, &val)
	return
}

func (p *KeyringProvider) Store(val credentials.Value) error {
	p.Keyring.Remove(sessionKey(p.Profile))

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
	p.Keyring.Remove(sessionKey(p.Profile))
	return p.Keyring.Remove(p.Profile)
}

type VaultCredentials struct {
	*credentials.Credentials
	provider *VaultProvider
}

func NewVaultCredentials(k keyring.Keyring, profile string, d time.Duration) (*VaultCredentials, error) {
	provider, err := NewVaultProvider(k, profile, d)
	if err != nil {
		return nil, err
	}

	return &VaultCredentials{credentials.NewCredentials(provider), provider}, nil
}

func (v *VaultCredentials) Expires() time.Time {
	return v.provider.expires
}
