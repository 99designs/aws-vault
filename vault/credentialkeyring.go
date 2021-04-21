package vault

import (
	"encoding/json"
	"fmt"

	"github.com/99designs/keyring"
	"github.com/aws/aws-sdk-go-v2/aws"
)

type CredentialKeyring struct {
	Keyring keyring.Keyring
}

func (ck *CredentialKeyring) Keys() (credentialsNames []string, err error) {
	allKeys, err := ck.Keyring.Keys()
	if err != nil {
		return credentialsNames, err
	}
	for _, keyName := range allKeys {
		if !IsSessionKey(keyName) && !IsOIDCTokenKey(keyName) {
			credentialsNames = append(credentialsNames, keyName)
		}
	}
	return credentialsNames, nil
}

func (ck *CredentialKeyring) Has(credentialsName string) (bool, error) {
	allKeys, err := ck.Keyring.Keys()
	if err != nil {
		return false, err
	}
	for _, keyName := range allKeys {
		if keyName == credentialsName {
			return true, nil
		}
	}
	return false, nil
}

func (ck *CredentialKeyring) Get(credentialsName string) (creds aws.Credentials, err error) {
	item, err := ck.Keyring.Get(credentialsName)
	if err != nil {
		return creds, err
	}
	if err = json.Unmarshal(item.Data, &creds); err != nil {
		return creds, fmt.Errorf("Invalid data in keyring: %v", err)
	}
	return creds, err
}

func (ck *CredentialKeyring) Set(credentialsName string, creds aws.Credentials) error {
	bytes, err := json.Marshal(creds)
	if err != nil {
		return err
	}

	return ck.Keyring.Set(keyring.Item{
		Key:   credentialsName,
		Label: fmt.Sprintf("aws-vault (%s)", credentialsName),
		Data:  bytes,

		// specific Keychain settings
		KeychainNotTrustApplication: true,
	})
}

func (ck *CredentialKeyring) Remove(credentialsName string) error {
	return ck.Keyring.Remove(credentialsName)
}
