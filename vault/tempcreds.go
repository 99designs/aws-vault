package vault

import (
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/99designs/aws-vault/prompt"
	"github.com/99designs/keyring"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
)

const DefaultExpirationWindow = 5 * time.Minute

func newSession(creds *credentials.Credentials, region string) (*session.Session, error) {
	return session.NewSession(aws.NewConfig().WithRegion(region).WithCredentials(creds))
}

func formatKeyForDisplay(k string) string {
	return fmt.Sprintf("****************%s", k[len(k)-4:])
}

// NewTempCredentials creates temporary credentials
func NewTempCredentials(k keyring.Keyring, config *Config) (*credentials.Credentials, error) {
	provider, err := NewTempCredentialsProvider(k, config)
	if err != nil {
		return nil, err
	}

	return credentials.NewCredentials(provider), nil
}

// NewTempCredentials creates a provider for temporary credentials
func NewTempCredentialsProvider(k keyring.Keyring, config *Config) (*TempCredentialsProvider, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	return &TempCredentialsProvider{
		masterCreds: NewMasterCredentials(k, config.CredentialsName),
		config:      config,
		sessions:    &KeyringSessions{k},
	}, nil
}

// TempCredentialsProvider provides credentials protected by GetSessionToken and AssumeRole where possible
type TempCredentialsProvider struct {
	credentials.Expiry
	masterCreds         *credentials.Credentials
	sessions            *KeyringSessions
	config              *Config
	forceSessionRefresh bool
}

func (p *TempCredentialsProvider) ForceRefresh() {
	p.masterCreds.Expire()
	p.forceSessionRefresh = true
}

func (p *TempCredentialsProvider) Retrieve() (credentials.Value, error) {
	if p.config.NoSession && p.config.RoleARN == "" {
		log.Println("Using master credentials")
		return p.masterCreds.Get()
	}
	if p.config.NoSession {
		return p.getCredsWithRole()
	}
	if p.config.RoleARN == "" {
		return p.getCredsWithSession()
	}

	return p.getCredsWithSessionAndRole()
}

func (p *TempCredentialsProvider) getCredsWithSession() (credentials.Value, error) {
	log.Println("Getting credentials with GetSessionToken")

	session, err := p.getSessionToken()
	if err != nil {
		return credentials.Value{}, err
	}

	p.SetExpiration(*session.Expiration, DefaultExpirationWindow)

	value := credentials.Value{
		AccessKeyID:     *session.AccessKeyId,
		SecretAccessKey: *session.SecretAccessKey,
		SessionToken:    *session.SessionToken,
	}

	log.Printf("Using session token %s, expires in %s", formatKeyForDisplay(*session.AccessKeyId), time.Until(*session.Expiration).String())
	return value, nil
}

func (p *TempCredentialsProvider) getCredsWithSessionAndRole() (credentials.Value, error) {
	log.Println("Getting credentials with GetSessionToken and AssumeRole")

	session, err := p.getSessionToken()
	if err != nil {
		return credentials.Value{}, err
	}

	sessionCreds := credentials.NewStaticCredentials(*session.AccessKeyId, *session.SecretAccessKey, *session.SessionToken)
	role, err := p.assumeRoleFromCreds(sessionCreds, false)
	if err != nil {
		return credentials.Value{}, err
	}

	p.SetExpiration(*role.Expiration, DefaultExpirationWindow)

	creds := credentials.Value{
		AccessKeyID:     *role.AccessKeyId,
		SecretAccessKey: *role.SecretAccessKey,
		SessionToken:    *role.SessionToken,
	}

	log.Printf("Using session token %s with role %s, expires in %s",
		formatKeyForDisplay(*session.AccessKeyId),
		formatKeyForDisplay(*role.AccessKeyId),
		time.Until(*role.Expiration).String())

	return creds, nil
}

// getCredsWithRole returns credentials a session created with AssumeRole
func (p *TempCredentialsProvider) getCredsWithRole() (credentials.Value, error) {
	log.Println("Getting credentials with AssumeRole")

	if p.config.RoleARN == "" {
		return credentials.Value{}, errors.New("No role defined")
	}

	role, err := p.assumeRoleFromCreds(p.masterCreds, true)
	if err != nil {
		return credentials.Value{}, err
	}

	p.SetExpiration(*role.Expiration, DefaultExpirationWindow)

	log.Printf("Using role %s, expires in %s", formatKeyForDisplay(*role.AccessKeyId), time.Until(*role.Expiration).String())
	return credentials.Value{
		AccessKeyID:     *role.AccessKeyId,
		SecretAccessKey: *role.SecretAccessKey,
		SessionToken:    *role.SessionToken,
	}, nil
}

func (p *TempCredentialsProvider) createSessionToken() (*sts.Credentials, error) {
	log.Printf("Creating new session token for profile %s", p.config.CredentialsName)
	var err error

	input := &sts.GetSessionTokenInput{
		DurationSeconds: aws.Int64(int64(p.config.SessionDuration.Seconds())),
	}

	if p.config.MfaSerial != "" {
		input.SerialNumber = aws.String(p.config.MfaSerial)
		input.TokenCode, err = getMfaToken(p.config)
		if err != nil {
			return nil, err
		}
	}

	sess, err := newSession(p.masterCreds, p.config.Region)
	if err != nil {
		return nil, err
	}
	client := sts.New(sess)

	resp, err := client.GetSessionToken(input)
	if err != nil {
		return nil, err
	}

	return resp.Credentials, nil
}

func (p *TempCredentialsProvider) getSessionToken() (*sts.Credentials, error) {
	if p.forceSessionRefresh {
		return p.createSessionToken()
	}

	session, err := p.sessions.Retrieve(p.config.CredentialsName, p.config.MfaSerial)
	if err != nil {
		// session lookup missed, we need to create a new one.
		session, err = p.createSessionToken()
		if err != nil {
			return nil, err
		}

		err = p.sessions.Store(p.config.CredentialsName, p.config.MfaSerial, session)
		if err != nil {
			return nil, err
		}
	}

	return session, err
}

func (p *TempCredentialsProvider) roleSessionName() string {
	if p.config.RoleSessionName != "" {
		return p.config.RoleSessionName
	}

	// Try to work out a role name that will hopefully end up unique.
	return fmt.Sprintf("%d", time.Now().UTC().UnixNano())
}

// assumeRoleFromCreds uses the master credentials to assume a role
func (p *TempCredentialsProvider) assumeRoleFromCreds(creds *credentials.Credentials, includeMfa bool) (*sts.Credentials, error) {
	var err error
	sess, err := newSession(creds, p.config.Region)
	if err != nil {
		return nil, err
	}
	client := sts.New(sess)

	input := &sts.AssumeRoleInput{
		RoleArn:         aws.String(p.config.RoleARN),
		RoleSessionName: aws.String(p.roleSessionName()),
		DurationSeconds: aws.Int64(int64(p.config.AssumeRoleDuration.Seconds())),
	}

	if p.config.ExternalID != "" {
		input.ExternalId = aws.String(p.config.ExternalID)
	}

	// if we don't have a session, we need to include MFA token in the AssumeRole call
	if includeMfa && p.config.MfaSerial != "" {
		input.SerialNumber = aws.String(p.config.MfaSerial)
		input.TokenCode, err = getMfaToken(p.config)
		if err != nil {
			return nil, err
		}
	}

	log.Printf("Assuming role %s", p.config.RoleARN)
	resp, err := client.AssumeRole(input)
	if err != nil {
		return nil, err
	}

	return resp.Credentials, nil
}

func getMfaToken(c *Config) (*string, error) {
	if c.MfaToken != "" {
		return aws.String(c.MfaToken), nil
	}

	if c.MfaPromptMethod != "" {
		promptFunc := prompt.Method(c.MfaPromptMethod)
		token, err := promptFunc(fmt.Sprintf("Enter token for %s: ", c.MfaSerial))
		return aws.String(token), err
	}

	return nil, errors.New("No prompt found")
}
