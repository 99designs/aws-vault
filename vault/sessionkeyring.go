package vault

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/99designs/keyring"
	"github.com/aws/aws-sdk-go/service/sts"
)

var sessionKeyPattern = regexp.MustCompile(`^(?P<type>[^,]+),(?P<profile>[^,]+),(?P<mfaSerial>[^,]*),(?P<expiration>[0-9]{1,})$`)

var oldSessionKeyPatterns = []*regexp.Regexp{
	regexp.MustCompile(`^session,(?P<profile>[^,]+),(?P<mfaSerial>[^,]*),(?P<expiration>[0-9]{2,})$`),
	regexp.MustCompile(`^session:(?P<profile>[^ ]+):(?P<mfaSerial>[^ ]*):(?P<expiration>[^:]+)$`),
	regexp.MustCompile(`^(.+?) session \((\d+)\)$`),
}
var base64URLEncodingNoPadding = base64.URLEncoding.WithPadding(base64.NoPadding)

func IsOldSessionKey(s string) bool {
	for _, pattern := range oldSessionKeyPatterns {
		if pattern.MatchString(s) {
			return true
		}
	}
	return false
}

func IsCurrentSessionKey(s string) bool {
	_, err := NewSessionKeyFromString(s)
	return err == nil
}

func IsSessionKey(s string) bool {
	return IsCurrentSessionKey(s) || IsOldSessionKey(s)
}

type SessionMetadata struct {
	Type        string
	ProfileName string
	MfaSerial   string
	Expiration  time.Time
}

func (k *SessionMetadata) String() string {
	return fmt.Sprintf(
		"%s,%s,%s,%d",
		k.Type,
		base64URLEncodingNoPadding.EncodeToString([]byte(k.ProfileName)),
		base64URLEncodingNoPadding.EncodeToString([]byte(k.MfaSerial)),
		k.Expiration.Unix(),
	)
}

func (k *SessionMetadata) StringForMatching() string {
	return fmt.Sprintf(
		"%s,%s,%s,",
		k.Type,
		base64URLEncodingNoPadding.EncodeToString([]byte(k.ProfileName)),
		base64URLEncodingNoPadding.EncodeToString([]byte(k.MfaSerial)),
	)
}

func NewSessionKeyFromString(s string) (SessionMetadata, error) {
	matches := sessionKeyPattern.FindStringSubmatch(s)
	if len(matches) == 0 {
		return SessionMetadata{}, fmt.Errorf("failed to parse session name: %s", s)
	}

	profileName, err := base64URLEncodingNoPadding.DecodeString(matches[2])
	if err != nil {
		return SessionMetadata{}, err
	}
	mfaSerial, err := base64URLEncodingNoPadding.DecodeString(matches[3])
	if err != nil {
		return SessionMetadata{}, err
	}
	expiryUnixtime, err := strconv.Atoi(matches[4])
	if err != nil {
		return SessionMetadata{}, err
	}

	return SessionMetadata{
		Type:        matches[1],
		ProfileName: string(profileName),
		MfaSerial:   string(mfaSerial),
		Expiration:  time.Unix(int64(expiryUnixtime), 0),
	}, nil
}

type SessionKeyring struct {
	Keyring keyring.Keyring
}

var ErrNotFound = keyring.ErrKeyNotFound

func (sk *SessionKeyring) lookupKeyName(key SessionMetadata) (string, error) {
	allKeys, err := sk.Keyring.Keys()
	if err != nil {
		return key.String(), err
	}
	for _, keyName := range allKeys {
		if strings.HasPrefix(keyName, key.StringForMatching()) {
			return keyName, nil
		}
	}
	return key.String(), ErrNotFound
}

func (sk *SessionKeyring) Has(key SessionMetadata) (bool, error) {
	_, err := sk.lookupKeyName(key)
	if err == ErrNotFound {
		return false, nil
	}
	if err == nil {
		return true, nil
	}

	return false, err
}

func (sk *SessionKeyring) Get(key SessionMetadata) (val *sts.Credentials, err error) {
	sk.RemoveOldSessions()

	keyName, err := sk.lookupKeyName(key)
	if err != nil && err != ErrNotFound {
		return nil, err
	}
	item, err := sk.Keyring.Get(keyName)
	if err != nil {
		return val, err
	}
	if err = json.Unmarshal(item.Data, &val); err != nil {
		log.Printf("SessionKeyring: Ignoring invalid data: %s", err.Error())
		return val, ErrNotFound
	}
	return val, err
}

func (sk *SessionKeyring) Set(key SessionMetadata, val *sts.Credentials) error {
	sk.RemoveOldSessions()

	key.Expiration = *val.Expiration

	valJson, err := json.Marshal(val)
	if err != nil {
		return err
	}

	keyName, err := sk.lookupKeyName(key)
	if err != ErrNotFound {
		if err != nil {
			return err
		}
		if keyName != key.String() {
			err = sk.Keyring.Remove(keyName)
			if err != nil {
				return err
			}
		}
	}

	return sk.Keyring.Set(keyring.Item{
		Key:         key.String(),
		Data:        valJson,
		Label:       fmt.Sprintf("aws-vault session for %s (expires %s)", key.ProfileName, val.Expiration.Format(time.RFC3339)),
		Description: "aws-vault session",
	})
}

func (sk *SessionKeyring) Remove(key SessionMetadata) error {
	keyName, err := sk.lookupKeyName(key)
	if err != nil && err != ErrNotFound {
		return err
	}

	return sk.Keyring.Remove(keyName)
}

func (sk *SessionKeyring) RemoveAll() (n int, err error) {
	allKeys, err := sk.Keys()
	if err != nil {
		return 0, err
	}
	for _, key := range allKeys {
		if err = sk.Remove(key); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

func (sk *SessionKeyring) Keys() (kk []SessionMetadata, err error) {
	allKeys, err := sk.Keyring.Keys()
	if err != nil {
		return nil, err
	}

	for _, s := range allKeys {
		if k, err := NewSessionKeyFromString(s); err == nil {
			kk = append(kk, k)
		}
	}

	return kk, nil
}

func (sk *SessionKeyring) realSessionKey(key SessionMetadata) (m SessionMetadata, err error) {
	keyName, err := sk.lookupKeyName(key)
	if err != nil {
		return m, err
	}
	sessKey, err := NewSessionKeyFromString(keyName)
	if err != nil {
		return m, err
	}
	return sessKey, nil
}

func (sk *SessionKeyring) GetAllMetadata() (mm []SessionMetadata, err error) {
	allKeys, err := sk.Keys()
	if err != nil {
		return nil, err
	}

	for _, k := range allKeys {
		m, err := sk.realSessionKey(k)
		if err != nil {
			return nil, fmt.Errorf("GetAllMetadata: %w", err)
		}

		mm = append(mm, m)
	}

	return mm, nil
}

func (sk *SessionKeyring) RemoveForProfile(profileName string) (n int, err error) {
	sessions, err := sk.GetAllMetadata()
	if err != nil {
		return n, err
	}
	for _, s := range sessions {
		if s.ProfileName == profileName {
			err = sk.Remove(s)
			if err != nil {
				return n, err
			}
			n++
		}
	}

	return n, nil
}

func (sk *SessionKeyring) RemoveOldSessions() (n int, err error) {
	allKeys, err := sk.Keyring.Keys()
	if err != nil {
		log.Printf("Error while deleting old session: %s", err.Error())
	}

	for _, k := range allKeys {
		if IsOldSessionKey(k) {
			err = sk.Keyring.Remove(k)
			if err != nil {
				log.Printf("Error while deleting old session: %s", err.Error())
				continue
			}
			n++
		} else {
			stsk, err := NewSessionKeyFromString(k)
			if err != nil {
				continue
			}
			if time.Now().After(stsk.Expiration) {
				err = sk.Keyring.Remove(k)
				if err != nil {
					log.Printf("Error while deleting old session: %s", err.Error())
					continue
				}
				n++
			}
		}
	}

	return n, nil
}
