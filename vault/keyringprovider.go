package vault

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/99designs/keyring"
	"github.com/aws/aws-sdk-go/aws/credentials"
)

// KeyringProvider stores and retrieves master credentials
type KeyringProvider struct {
	Keyring         keyring.Keyring
	CredentialsName string
}

func (p *KeyringProvider) IsExpired() bool {
	return false
}

func (p *KeyringProvider) Retrieve() (val credentials.Value, err error) {
	log.Printf("Looking up keyring for %s", p.CredentialsName)
	item, err := p.Keyring.Get(p.CredentialsName)
	if err != nil {
		log.Println("Error from keyring", err)
		return val, err
	}
	if err = json.Unmarshal(item.Data, &val); err != nil {
		return val, fmt.Errorf("Invalid data in keyring: %v", err)
	}
	return val, err
}

func (p *KeyringProvider) Store(val credentials.Value) error {
	bytes, err := json.Marshal(val)
	if err != nil {
		return err
	}

	return p.Keyring.Set(keyring.Item{
		Key:   p.CredentialsName,
		Label: fmt.Sprintf("aws-vault (%s)", p.CredentialsName),
		Data:  bytes,

		// specific Keychain settings
		KeychainNotTrustApplication: true,
	})
}

func (p *KeyringProvider) Delete() error {
	return p.Keyring.Remove(p.CredentialsName)
}
