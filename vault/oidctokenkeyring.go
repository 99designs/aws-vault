package vault

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/99designs/keyring"
	"github.com/aws/aws-sdk-go/service/ssooidc"
)

type OIDCTokenKeyring struct {
	Keyring keyring.Keyring
}

type OIDCTokenData struct {
	Token      ssooidc.CreateTokenOutput
	Expiration time.Time
}

const oidcTokenKeyPrefix = "oidc:"

func (o *OIDCTokenKeyring) fmtKey(startURL string) string {
	return oidcTokenKeyPrefix + startURL
}

func IsOIDCTokenKey(k string) bool {
	return strings.HasPrefix(k, oidcTokenKeyPrefix)
}

func (o OIDCTokenKeyring) Has(startURL string) (bool, error) {
	kk, err := o.Keyring.Keys()
	if err != nil {
		return false, err
	}

	for _, k := range kk {
		if startURL == k {
			return true, nil
		}
	}

	return false, nil
}

func (o OIDCTokenKeyring) Get(startURL string) (*ssooidc.CreateTokenOutput, error) {
	item, err := o.Keyring.Get(o.fmtKey(startURL))
	if err != nil {
		return nil, err
	}

	val := OIDCTokenData{}

	if err = json.Unmarshal(item.Data, &val); err != nil {
		log.Printf("Invalid data in keyring: %s", err.Error())
		return nil, keyring.ErrKeyNotFound
	}
	if time.Now().After(val.Expiration) {
		log.Printf("OIDC token for '%s' expired, removing", startURL)
		_ = o.Remove(startURL)
		return nil, keyring.ErrKeyNotFound
	}

	secondsLeft := int64(time.Until(val.Expiration) / time.Second)

	val.Token.ExpiresIn = &secondsLeft

	return &val.Token, err
}

func (o OIDCTokenKeyring) Set(startURL string, token *ssooidc.CreateTokenOutput) error {
	val := OIDCTokenData{
		Token:      *token,
		Expiration: time.Now().Add(time.Duration(*token.ExpiresIn) * time.Second),
	}

	valJson, err := json.Marshal(val)
	if err != nil {
		return err
	}

	return o.Keyring.Set(keyring.Item{
		Key:         o.fmtKey(startURL),
		Data:        valJson,
		Label:       fmt.Sprintf("aws-vault oidc token for %s (expires %s)", startURL, val.Expiration.Format(time.RFC3339)),
		Description: "aws-vault oidc token",
	})
}

func (o OIDCTokenKeyring) Remove(startURL string) error {
	return o.Keyring.Remove(o.fmtKey(startURL))
}

func (o *OIDCTokenKeyring) RemoveAll() (n int, err error) {
	allKeys, err := o.Keys()
	if err != nil {
		return 0, err
	}
	for _, key := range allKeys {
		if err = o.Remove(key); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

func (o *OIDCTokenKeyring) Keys() (kk []string, err error) {
	allKeys, err := o.Keyring.Keys()
	if err != nil {
		return nil, err
	}

	for _, k := range allKeys {
		if IsOIDCTokenKey(k) {
			kk = append(kk, strings.TrimPrefix(k, oidcTokenKeyPrefix))
		}
	}

	return kk, nil
}
