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

const OIDCTokenKeyringPrefix = "oidc:"

type OIDCTokenKeyring struct {
	Keyring keyring.Keyring
}

type OIDCTokenData struct {
	Token      ssooidc.CreateTokenOutput
	Expiration time.Time
}

func IsOIDCTokenKeyringKey(raw string) bool {
	return strings.HasPrefix(raw, OIDCTokenKeyringPrefix)
}

func (o *OIDCTokenKeyring) keyToStartURL(raw string) string {
	return strings.TrimPrefix(raw, OIDCTokenKeyringPrefix)
}

func (o *OIDCTokenKeyring) key(startURL string) string {
	return OIDCTokenKeyringPrefix + startURL
}

func (o OIDCTokenKeyring) Get(startURLorKey string) (*ssooidc.CreateTokenOutput, error) {
	var startURL string
	if IsOIDCTokenKeyringKey(startURLorKey) {
		startURL = o.keyToStartURL(startURLorKey)
	}
	item, err := o.Keyring.Get(o.key(startURL))
	if err != nil {
		return nil, err
	}

	val := OIDCTokenData{}

	if err = json.Unmarshal(item.Data, &val); err != nil {
		return nil, fmt.Errorf("Invalid data in keyring: %w", err)
	}
	if time.Now().After(val.Expiration) {
		log.Printf("OIDC token for '%s' expired, removing", startURL)
		_ = o.Remove(startURL)
		return nil, fmt.Errorf("Token expired")
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
		Key:         o.key(startURL),
		Data:        valJson,
		Label:       fmt.Sprintf("aws-vault oidc token for %s (expires %s)", startURL, val.Expiration.Format(time.RFC3339)),
		Description: "aws-vault oidc token",
	})
}

func (o OIDCTokenKeyring) Remove(startURL string) error {
	return o.Keyring.Remove(o.key(startURL))
}
