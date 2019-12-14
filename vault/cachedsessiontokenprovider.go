package vault

import (
	"log"
	"time"

	"github.com/99designs/keyring"
	"github.com/aws/aws-sdk-go/aws/credentials"
)

// CachedSessionTokenProvider retrieves cached credentials in the keyring, or temporary credentials using STS GetSessionToken
type CachedSessionTokenProvider struct {
	CredentialsName string
	Provider        *SessionTokenProvider
	Keyring         keyring.Keyring
	credentials.Expiry
}

// Retrieve returns cached credentials in the keyring, or temporary credentials using STS GetSessionToken
func (p *CachedSessionTokenProvider) Retrieve() (credentials.Value, error) {
	sessions := NewKeyringSessions(p.Keyring)

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
		log.Printf("Re-using cached session token %s, expires in %s", formatKeyForDisplay(*session.AccessKeyId), time.Until(*session.Expiration).String())
	}

	p.SetExpiration(*session.Expiration, DefaultExpirationWindow)

	return credentials.Value{
		AccessKeyID:     *session.AccessKeyId,
		SecretAccessKey: *session.SecretAccessKey,
		SessionToken:    *session.SessionToken,
	}, nil
}
