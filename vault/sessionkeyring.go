package vault

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"time"

	"github.com/99designs/keyring"
	"github.com/aws/aws-sdk-go/service/sts"
)

var sessionKeyPattern = regexp.MustCompile(`^(?P<type>[^,]+),(?P<profile>[^,]+),(?P<mfaSerial>[^,]*),0$`)

var oldSessionKeyPatterns = []*regexp.Regexp{
	regexp.MustCompile(`^session,(?P<profile>[^,]+),(?P<mfaSerial>[^,]*),(?P<expiration>[0-9]{2,})$`),
	regexp.MustCompile(`^session:(?P<profile>[^ ]+):(?P<mfaSerial>[^ ]*):(?P<expiration>[^:]+)$`),
	regexp.MustCompile(`^(.+?) session \((\d+)\)$`),
}
var base64Encoding = base64.URLEncoding.WithPadding(base64.NoPadding)

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

type SessionKey struct {
	Type        string
	ProfileName string
	MfaSerial   string
}

func (k *SessionKey) String() string {
	return fmt.Sprintf(
		"%s,%s,%s,0",
		k.Type,
		base64Encoding.EncodeToString([]byte(k.ProfileName)),
		base64Encoding.EncodeToString([]byte(k.MfaSerial)),
	)
}

func NewSessionKeyFromString(s string) (SessionKey, error) {
	matches := sessionKeyPattern.FindStringSubmatch(s)
	if len(matches) == 0 {
		return SessionKey{}, fmt.Errorf("failed to parse session name: %s", s)
	}

	profileName, err := base64Encoding.DecodeString(matches[2])
	if err != nil {
		return SessionKey{}, err
	}
	mfaSerial, err := base64Encoding.DecodeString(matches[3])
	if err != nil {
		return SessionKey{}, err
	}

	return SessionKey{
		Type:        matches[1],
		ProfileName: string(profileName),
		MfaSerial:   string(mfaSerial),
	}, nil
}

type SessionMetadata struct {
	SessionKey
	Expiration time.Time
}

type SessionKeyring struct {
	Keyring            keyring.Keyring
	isGarbageCollected bool
}

func (sk *SessionKeyring) Has(key SessionKey) (bool, error) {
	allKeys, err := sk.Keyring.Keys()
	if err != nil {
		return false, err
	}
	for _, keyName := range allKeys {
		if keyName == key.String() {
			return true, nil
		}
	}
	return false, nil
}

func (sk *SessionKeyring) Get(key SessionKey) (val *sts.Credentials, err error) {
	sk.GarbageCollectOnce()

	item, err := sk.Keyring.Get(key.String())
	if err != nil {
		return val, err
	}
	if err = json.Unmarshal(item.Data, &val); err != nil {
		return val, fmt.Errorf("Invalid data in keyring: %w", err)
	}
	return val, err
}

func (sk *SessionKeyring) Set(key SessionKey, val *sts.Credentials) error {
	sk.GarbageCollectOnce()

	valJson, err := json.Marshal(val)
	if err != nil {
		return err
	}

	return sk.Keyring.Set(keyring.Item{
		Key:         key.String(),
		Data:        valJson,
		Label:       fmt.Sprintf("aws-vault session for %s (expires %s)", key.ProfileName, val.Expiration.Format(time.RFC3339)),
		Description: "aws-vault session",
	})
}

func (sk *SessionKeyring) Remove(key SessionKey) error {
	sk.GarbageCollectOnce()
	return sk.Keyring.Remove(key.String())
}

func (sk *SessionKeyring) Keys() (kk []SessionKey, err error) {
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

func (sk *SessionKeyring) RemoveAll() error {
	allKeys, err := sk.Keys()
	if err != nil {
		return err
	}
	for _, k := range allKeys {
		err = sk.Remove(k)
		if err != nil {
			return err
		}
	}

	return nil
}

func (sk *SessionKeyring) GetMetadata(key SessionKey) (m SessionMetadata, err error) {
	item, err := sk.Keyring.GetMetadata(key.String())
	if err != nil {
		return m, fmt.Errorf("GetMetadata: %s: %w", key.String(), err)
	}

	matches := regexp.MustCompile(`\(expires (.+)\)$`).FindStringSubmatch(item.Label)
	if len(matches) == 0 {
		return m, fmt.Errorf("failed to parse session label: %s", item.Label)
	}

	m.SessionKey = key
	m.Expiration, _ = time.Parse(time.RFC3339, matches[1])

	return m, nil
}

func (sk *SessionKeyring) GetAllMetadata() (mm []SessionMetadata, err error) {
	allKeys, err := sk.Keys()
	if err != nil {
		return nil, err
	}

	for _, k := range allKeys {
		m, err := sk.GetMetadata(k)
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
			err = sk.Remove(s.SessionKey)
			if err != nil {
				return n, err
			}
			n++
		}
	}

	return n, nil
}

func (sk *SessionKeyring) GarbageCollectOnce() (n int, err error) {
	if sk.isGarbageCollected {
		return
	}
	sk.isGarbageCollected = true

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
			m, err := sk.GetMetadata(stsk)
			if err != nil {
				log.Printf("Error while deleting old session: %s", err.Error())
				continue
			}
			if time.Now().After(m.Expiration) {
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
