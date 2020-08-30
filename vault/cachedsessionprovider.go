package vault

import (
	"log"
	"time"

	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/service/sts"
)

// CachedSessionProvider retrieves cached credentials from the keyring, or if no credentials are cached
// retrieves temporary credentials using the CredentialsFunc
type CachedSessionProvider struct {
	SessionKey      SessionMetadata
	CredentialsFunc func() (*sts.Credentials, error)
	Keyring         *SessionKeyring
	ExpiryWindow    time.Duration
	credentials.Expiry
}

// Retrieve returns cached credentials from the keyring, or if no credentials are cached
// generates a new set of temporary credentials using the CredentialsFunc
func (p *CachedSessionProvider) Retrieve() (credentials.Value, error) {
	creds, err := p.Keyring.Get(p.SessionKey)

	if err != nil || time.Until(*creds.Expiration) < p.ExpiryWindow {
		// lookup missed, we need to create a new one.
		creds, err = p.CredentialsFunc()
		if err != nil {
			return credentials.Value{}, err
		}
		err = p.Keyring.Set(p.SessionKey, creds)
		if err != nil {
			return credentials.Value{}, err
		}
	} else {
		log.Printf("Re-using cached credentials %s from %s, expires in %s", FormatKeyForDisplay(*creds.AccessKeyId), p.SessionKey.Type, time.Until(*creds.Expiration).String())
	}

	p.SetExpiration(*creds.Expiration, p.ExpiryWindow)

	return credentials.Value{
		AccessKeyID:     *creds.AccessKeyId,
		SecretAccessKey: *creds.SecretAccessKey,
		SessionToken:    *creds.SessionToken,
	}, nil
}
