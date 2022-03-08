package vault

import (
	"context"
	"log"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
)

// CachedSessionProvider retrieves cached credentials from the keyring, or if no credentials are cached
// retrieves temporary credentials using the CredentialsFunc
type CachedSessionProvider struct {
	SessionKey      SessionMetadata
	CredentialsFunc func(context.Context) (*ststypes.Credentials, error)
	Keyring         *SessionKeyring
	ExpiryWindow    time.Duration
}

// Retrieve returns cached credentials from the keyring, or if no credentials are cached
// generates a new set of temporary credentials using the CredentialsFunc
func (p *CachedSessionProvider) Retrieve(ctx context.Context) (aws.Credentials, error) {
	creds, err := p.Keyring.Get(p.SessionKey)

	if err != nil || time.Until(*creds.Expiration) < p.ExpiryWindow {
		// lookup missed, we need to create a new one.
		creds, err = p.CredentialsFunc(ctx)
		if err != nil {
			return aws.Credentials{}, err
		}
		err = p.Keyring.Set(p.SessionKey, creds)
		if err != nil {
			return aws.Credentials{}, err
		}
	} else {
		log.Printf("Re-using cached credentials %s from %s, expires in %s", FormatKeyForDisplay(*creds.AccessKeyId), p.SessionKey.Type, time.Until(*creds.Expiration).String())
	}

	return aws.Credentials{
		AccessKeyID:     aws.ToString(creds.AccessKeyId),
		SecretAccessKey: aws.ToString(creds.SecretAccessKey),
		SessionToken:    aws.ToString(creds.SessionToken),
		CanExpire:       true,
		Expires:         aws.ToTime(creds.Expiration),
	}, nil
}
