package vault

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/99designs/keyring"
	"github.com/aws/aws-sdk-go/aws/credentials"
)

func NewMasterCredentials(k keyring.Keyring, credentialsName string) *credentials.Credentials {
	return credentials.NewCredentials(NewMasterCredentialsProvider(k, credentialsName))
}

func NewMasterCredentialsProvider(k keyring.Keyring, credentialsName string) *MasterCredentialsProvider {
	return &MasterCredentialsProvider{k, credentialsName}
}

// MasterCredentialsProvider stores and retrieves master credentials
type MasterCredentialsProvider struct {
	keyring         keyring.Keyring
	credentialsName string
}

func (p *MasterCredentialsProvider) IsExpired() bool {
	return false
}

func (p *MasterCredentialsProvider) Retrieve() (val credentials.Value, err error) {
	log.Printf("Looking up keyring for %s", p.credentialsName)
	item, err := p.keyring.Get(p.credentialsName)
	if err != nil {
		log.Println("Error from keyring", err)
		return val, err
	}
	if err = json.Unmarshal(item.Data, &val); err != nil {
		return val, fmt.Errorf("Invalid data in keyring: %v", err)
	}
	return val, err
}

func (p *MasterCredentialsProvider) Store(val credentials.Value) error {
	bytes, err := json.Marshal(val)
	if err != nil {
		return err
	}

	return p.keyring.Set(keyring.Item{
		Key:   p.credentialsName,
		Label: fmt.Sprintf("aws-vault (%s)", p.credentialsName),
		Data:  bytes,

		// specific Keychain settings
		KeychainNotTrustApplication: true,
	})
}

func (p *MasterCredentialsProvider) Delete() error {
	return p.keyring.Remove(p.credentialsName)
}
