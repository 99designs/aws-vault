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
	Keyring         *CredentialKeyring
	ExpiryWindow    time.Duration
	credentials.Expiry
}

// Retrieve returns cached credentials from the keyring, or if no credentials are cached
// generates a new set of temporary credentials using STS GetSessionToken
func (p *CachedSessionTokenProvider) Retrieve() (credentials.Value, error) {
	sessions := p.Keyring.Sessions()

	session, err := sessions.Retrieve(p.CredentialsName, p.Provider.MfaSerial)
	if err != nil {
		// session lookup missed, we need to create a new one.
		session, err = p.Provider.GetSessionToken()
		if err != nil {
			return credentials.Value{}, err
		}

		err = sessions.Store(p.CredentialsName, p.Provider.MfaSerial, session)
		if err != nil {
			return credentials.Value{}, err
		}
	} else {
		log.Printf("Re-using cached credentials %s generated from GetSessionToken, expires in %s", FormatKeyForDisplay(*session.AccessKeyId), time.Until(*session.Expiration).String())
	}

	p.SetExpiration(*session.Expiration, p.ExpiryWindow)

	return credentials.Value{
		AccessKeyID:     *session.AccessKeyId,
		SecretAccessKey: *session.SecretAccessKey,
		SessionToken:    *session.SessionToken,
	}, nil
}
