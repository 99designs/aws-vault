package vault

import (
	"log"
	"time"

	"github.com/aws/aws-sdk-go/aws/credentials"
)

// CachedSessionTokenProvider retrieves cached credentials from the keyring, or if no credentials are cached
// retrieves temporary credentials from STS using GetSessionToken
type CachedSessionTokenProvider struct {
	CredentialsName string
	Provider        *SessionTokenProvider
	Keyring         *SessionKeyring
	ExpiryWindow    time.Duration
	credentials.Expiry
}

// Retrieve returns cached credentials from the keyring, or if no credentials are cached
// generates a new set of temporary credentials using STS GetSessionToken
func (p *CachedSessionTokenProvider) Retrieve() (credentials.Value, error) {
	key := SessionKey{
		Type:        "session",
		ProfileName: p.CredentialsName,
		MfaSerial:   p.Provider.MfaSerial,
	}
	creds, err := p.Keyring.Get(key)
	if err != nil {
		// lookup missed, we need to create a new one.
		creds, err = p.Provider.GetSessionToken()
		if err != nil {
			return credentials.Value{}, err
		}
		err = p.Keyring.Set(key, creds)
		if err != nil {
			return credentials.Value{}, err
		}
	} else {
		log.Printf("Re-using cached credentials %s generated from GetSessionToken, expires in %s", FormatKeyForDisplay(*creds.AccessKeyId), time.Until(*creds.Expiration).String())
	}

	p.SetExpiration(*creds.Expiration, p.ExpiryWindow)

	return credentials.Value{
		AccessKeyID:     *creds.AccessKeyId,
		SecretAccessKey: *creds.SecretAccessKey,
		SessionToken:    *creds.SessionToken,
	}, nil
}
