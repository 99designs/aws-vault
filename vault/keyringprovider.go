package vault

import (
	"log"

	"github.com/aws/aws-sdk-go/aws/credentials"
)

// KeyringProvider stores and retrieves master credentials
type KeyringProvider struct {
	Keyring         *CredentialKeyring
	CredentialsName string
}

func (p *KeyringProvider) IsExpired() bool {
	return false
}

func (p *KeyringProvider) Retrieve() (val credentials.Value, err error) {
	log.Printf("Looking up keyring for '%s'", p.CredentialsName)
	return p.Keyring.Get(p.CredentialsName)
}
