package vault

import (
	"log"
	"time"

	"github.com/99designs/aws-vault/Godeps/_workspace/src/github.com/aws/aws-sdk-go/aws"
	"github.com/99designs/aws-vault/Godeps/_workspace/src/github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/99designs/aws-vault/Godeps/_workspace/src/github.com/aws/aws-sdk-go/service/sts"
	"github.com/99designs/aws-vault/keyring"
)

type TokenAgent interface {
	GetToken(serial string) (string, error)
}

type SessionConfig struct {
	Profile     *Profile
	TokenAgent  TokenAgent
	Duration    time.Duration
	Credentials *Credentials
	Refresh     bool
}

type SessionProvider struct {
}

func (sp *SessionProvider) Session(conf SessionConfig) (SessionCredentials, error) {
	awsConf := aws.DefaultConfig

	if conf.Credentials != nil {
		awsConf = awsConf.WithCredentials(credentials.NewStaticCredentials(
			conf.Credentials.AccessKeyId, conf.Credentials.SecretKey, "",
		))
	}

	svc := sts.New(awsConf)

	var serialNumber, token string

	if conf.Profile.MFASerial != "" && conf.TokenAgent != nil {
		var err error
		if token, err = conf.TokenAgent.GetToken(conf.Profile.MFASerial); err != nil {
			return SessionCredentials{}, err
		}
		serialNumber = conf.Profile.MFASerial
	}

	// handle assume role
	if conf.Profile.RoleARN != "" {
		input := &sts.AssumeRoleInput{
			RoleARN:         aws.String(conf.Profile.RoleARN),
			RoleSessionName: aws.String(conf.Profile.Name),
			DurationSeconds: aws.Int64(int64(conf.Duration.Seconds())),
			SerialNumber:    aws.String(serialNumber),
			TokenCode:       aws.String(token),
		}

		if token != "" {
			log.Printf("assuming role %s with mfa %s", conf.Profile.RoleARN, serialNumber)
		} else {
			log.Printf("assuming role %s", conf.Profile.RoleARN)
		}

		resp, err := svc.AssumeRole(input)
		if err != nil {
			log.Printf("%#v", err)
			return SessionCredentials{}, err
		}
		return SessionCredentials{resp.Credentials}, nil
	}

	// otherwise get a session token
	input := &sts.GetSessionTokenInput{
		DurationSeconds: aws.Int64(int64(conf.Duration.Seconds())),
		SerialNumber:    aws.String(serialNumber),
		TokenCode:       aws.String(token),
	}

	if token != "" {
		log.Printf("getting session token with mfa %s", serialNumber)
	} else {
		log.Printf("getting session token")
	}

	resp, err := svc.GetSessionToken(input)
	if err != nil {
		return SessionCredentials{}, err
	}

	return SessionCredentials{resp.Credentials}, nil
}

type KeyringSessionProvider struct {
	SessionProvider
	Keyring   keyring.Keyring
	CredsFunc func() (Credentials, error)
}

func (ksp *KeyringSessionProvider) Session(conf SessionConfig) (SessionCredentials, error) {
	var sessionCreds *SessionCredentials

	if !conf.Refresh {
		// look for cached session credentials first
		keyring.Unmarshal(ksp.Keyring, SessionServiceName, conf.Profile.Name, &sessionCreds)
	}

	if sessionCreds == nil || time.Now().After(*sessionCreds.Expiration) {
		log.Println("fetching new session")

		if ksp.CredsFunc != nil {
			creds, err := ksp.CredsFunc()
			if err != nil {
				return SessionCredentials{}, err
			}
			conf.Credentials = &creds
		}

		newCreds, err := ksp.SessionProvider.Session(conf)
		if err != nil {
			return SessionCredentials{}, err
		}

		// cache the session credentials for next time
		if err = keyring.Marshal(ksp.Keyring, SessionServiceName, conf.Profile.Name, &newCreds); err != nil {
			return SessionCredentials{}, err
		}

		sessionCreds = &newCreds
	} else {
		log.Printf("using cached session (expires in %s)", sessionCreds.Expiration.Sub(time.Now()))
	}

	return *sessionCreds, nil
}
