package vault

import (
	"errors"
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
	masterCreds *credentials.Credentials
	sessions    *KeyringSessions
	config      *Config
}

func NewVaultProvider(k keyring.Keyring, config *Config) (*VaultProvider, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	return &VaultProvider{
		masterCreds: credentials.NewCredentials(NewKeyringProvider(k, config.CredentialsName)),
		config:      config,
		sessions:    &KeyringSessions{k},
	}, nil
}

// Retrieve returns credentials protected by GetSessionToken and AssumeRole where possible
func (p *VaultProvider) Retrieve() (credentials.Value, error) {
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

func (p *VaultProvider) getCredsWithSession() (credentials.Value, error) {
	log.Println("Getting credentials with GetSessionToken")

	session, err := p.getSessionToken()
	if err != nil {
		return credentials.Value{}, nil
	}

	p.SetExpiration(*session.Expiration, DefaultExpirationWindow)

	value := credentials.Value{
		AccessKeyID:     *session.AccessKeyId,
		SecretAccessKey: *session.SecretAccessKey,
		SessionToken:    *session.SessionToken,
	}

	log.Printf("Using session token ****************%s, expires in %s", (*session.AccessKeyId)[len(*session.AccessKeyId)-4:], session.Expiration.Sub(time.Now()).String())
	return value, nil
}

func (p *VaultProvider) getCredsWithSessionAndRole() (credentials.Value, error) {
	log.Println("Getting credentials with GetSessionToken and AssumeRole")

	session, err := p.getSessionToken()
	if err != nil {
		return credentials.Value{}, nil
	}

	role, err := p.assumeRoleFromSession(session)
	if err != nil {
		return credentials.Value{}, err
	}

	p.SetExpiration(*role.Expiration, DefaultExpirationWindow)

	creds := credentials.Value{
		AccessKeyID:     *role.AccessKeyId,
		SecretAccessKey: *role.SecretAccessKey,
		SessionToken:    *role.SessionToken,
	}

	log.Printf("Using session token ****************%s with role ****************%s, expires in %s",
		(*session.AccessKeyId)[len(*session.AccessKeyId)-4:],
		(*role.AccessKeyId)[len(*role.AccessKeyId)-4:],
		role.Expiration.Sub(time.Now()).String())

	return creds, nil
}

// getCredsWithRole returns credentials a session created with AssumeRole
func (p *VaultProvider) getCredsWithRole() (credentials.Value, error) {
	log.Println("Getting credentials with AssumeRole")

	if p.config.RoleARN == "" {
		return credentials.Value{}, errors.New("No role defined")
	}

	creds, err := p.masterCreds.Get()
	if err != nil {
		return credentials.Value{}, err
	}

	role, err := p.assumeRoleFromCreds(creds)
	if err != nil {
		return credentials.Value{}, err
	}

	p.SetExpiration(*role.Expiration, DefaultExpirationWindow)

	creds = credentials.Value{
		AccessKeyID:     *role.AccessKeyId,
		SecretAccessKey: *role.SecretAccessKey,
		SessionToken:    *role.SessionToken,
	}

	log.Printf("Using role ****************%s, expires in %s", (*role.AccessKeyId)[len(*role.AccessKeyId)-4:], role.Expiration.Sub(time.Now()).String())
	return creds, nil
}

func (p *VaultProvider) createSessionToken() (sts.Credentials, error) {
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

	creds, err := p.masterCreds.Get()
	if err != nil {
		return sts.Credentials{}, err
	}

	client := newStsClient(credentials.NewStaticCredentialsFromCreds(creds), p.config.Region)

	log.Printf("Getting new session token for profile %s", p.config.CredentialsName)

	resp, err := client.GetSessionToken(params)
	if err != nil {
		return sts.Credentials{}, err
	}

	return *resp.Credentials, nil
}

func (p *VaultProvider) getSessionToken() (sts.Credentials, error) {
	session, err := p.sessions.Retrieve(p.config.CredentialsName, p.config.MfaSerial)
	if err != nil {
		// session lookup missed, we need to create a new one.
		session, err = p.createSessionToken()
		if err != nil {
			return sts.Credentials{}, err
		}

		err = p.sessions.Store(p.config.CredentialsName, p.config.MfaSerial, session)
		if err != nil {
			return sts.Credentials{}, err
		}
	}

	return session, err
}

func (p *VaultProvider) roleSessionName() string {
	if p.config.RoleSessionName != "" {
		return p.config.RoleSessionName
	}

	// Try to work out a role name that will hopefully end up unique.
	return fmt.Sprintf("%d", time.Now().UTC().UnixNano())
}

func newStsClient(creds *credentials.Credentials, region string) *sts.STS {
	return sts.New(session.New(aws.NewConfig().WithCredentials(creds).WithRegion(region)))
}

// assumeRoleFromSession takes a session created with GetSessionToken and uses that to assume a role
func (p *VaultProvider) assumeRoleFromSession(session sts.Credentials) (sts.Credentials, error) {
	client := newStsClient(credentials.NewStaticCredentials(*session.AccessKeyId, *session.SecretAccessKey, *session.SessionToken), p.config.Region)

	input := &sts.AssumeRoleInput{
		RoleArn:         aws.String(p.config.RoleARN),
		RoleSessionName: aws.String(p.roleSessionName()),
		DurationSeconds: aws.Int64(int64(p.config.AssumeRoleDuration.Seconds())),
	}

	if p.config.ExternalID != "" {
		input.ExternalId = aws.String(p.config.ExternalID)
	}

	log.Printf("Assuming role %s from session token", p.config.RoleARN)
	resp, err := client.AssumeRole(input)
	if err != nil {
		return sts.Credentials{}, err
	}

	return *resp.Credentials, nil
}

// assumeRoleFromCreds uses IAM credentials to assume a role
func (p *VaultProvider) assumeRoleFromCreds(creds credentials.Value) (sts.Credentials, error) {
	if p.config.RoleARN == "" {
		return sts.Credentials{}, errors.New("No role defined")
	}

	client := newStsClient(credentials.NewStaticCredentialsFromCreds(creds), p.config.Region)

	input := &sts.AssumeRoleInput{
		RoleArn:         aws.String(p.config.RoleARN),
		RoleSessionName: aws.String(p.roleSessionName()),
		DurationSeconds: aws.Int64(int64(p.config.AssumeRoleDuration.Seconds())),
	}

	if p.config.ExternalID != "" {
		input.ExternalId = aws.String(p.config.ExternalID)
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

	log.Printf("Assuming role %s with iam credentials", p.config.RoleARN)
	resp, err := client.AssumeRole(input)
	if err != nil {
		return sts.Credentials{}, err
	}

	return *resp.Credentials, nil
}

func NewVaultCredentials(k keyring.Keyring, config *Config) (*credentials.Credentials, error) {
	provider, err := NewVaultProvider(k, config)
	if err != nil {
		return nil, err
	}

	return credentials.NewCredentials(provider), nil
}
