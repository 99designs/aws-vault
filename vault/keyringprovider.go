package vault

import (
	"context"
	"log"

	"github.com/aws/aws-sdk-go-v2/aws"
)

// KeyringProvider stores and retrieves master credentials
type KeyringProvider struct {
	Keyring         *CredentialKeyring
	CredentialsName string
}

func (p *KeyringProvider) Retrieve(ctx context.Context) (aws.Credentials, error) {
	log.Printf("Looking up keyring for '%s'", p.CredentialsName)
	return p.Keyring.Get(p.CredentialsName)
}
