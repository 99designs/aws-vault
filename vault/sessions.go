package vault

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"regexp"
	"strconv"
	"time"

	"github.com/99designs/keyring"
	"github.com/aws/aws-sdk-go/service/sts"
)

var sessionKeyPattern = regexp.MustCompile(`^(.+?) session \((\d+)\)$`)

func IsSessionKey(s string) bool {
	return sessionKeyPattern.MatchString(s)
}

func parseKeyringSession(s string, conf *Config) (KeyringSession, error) {
	matches := sessionKeyPattern.FindStringSubmatch(s)
	if len(matches) == 0 {
		return KeyringSession{}, errors.New("Failed to parse session name")
	}
	profile, _ := conf.Profile(matches[1])
	return KeyringSession{Profile: profile, Name: s, SessionID: matches[2]}, nil
}

type KeyringSession struct {
	Profile
	Name      string
	SessionID string
}

func (ks KeyringSession) IsExpired() bool {
	// Older sessions were 20 characters long and opaque identifiers
	if len(ks.SessionID) == 20 {
		return true
	}
	// Now our session id's are timestamps
	tsInt, err := strconv.ParseInt(ks.SessionID, 10, 64)
	if err != nil {
		return true
	}
	log.Printf("Session %q expires in %v", ks.Name, time.Unix(tsInt, 0).Sub(time.Now()).String())
	return time.Now().After(time.Unix(tsInt, 0))
}

type KeyringSessions struct {
	Keyring keyring.Keyring
	Config  *Config
}

func NewKeyringSessions(k keyring.Keyring, cfg *Config) (*KeyringSessions, error) {
	return &KeyringSessions{
		Keyring: k,
		Config:  cfg,
	}, nil
}

func (s *KeyringSessions) Sessions() ([]KeyringSession, error) {
	log.Printf("Looking up all keys in keyring")
	keys, err := s.Keyring.Keys()
	if err != nil {
		return nil, err
	}

	var sessions []KeyringSession

	for _, k := range keys {
		if IsSessionKey(k) {
			log.Printf("%s is a session", k)
			ks, _ := parseKeyringSession(k, s.Config)
			if ks.IsExpired() {
				log.Printf("Session %s is expired", ks.Name)
				continue
			}

			sessions = append(sessions, ks)
		}
	}

	return sessions, nil
}

// Retrieve searches sessions for specific profile, expects the source profile to be provided
func (s *KeyringSessions) Retrieve(profile string) (creds sts.Credentials, err error) {
	log.Printf("Looking for sessions for %s", profile)
	sessions, err := s.Sessions()
	if err != nil {
		return creds, err
	}

	for _, session := range sessions {
		log.Printf("Comparing %s and %s", session.Profile.Name, profile)
		if session.Profile.Name == profile {
			log.Printf("Matched session %s", session.Name)

			item, err := s.Keyring.Get(session.Name)
			if err != nil {
				return creds, err
			}

			if err = json.Unmarshal(item.Data, &creds); err != nil {
				return creds, err
			}

			// double check the actual expiry time
			if creds.Expiration.Before(time.Now()) {
				log.Printf("Session %q is expired, deleting", session.Name)
				if err = s.Keyring.Remove(session.Profile.Name); err != nil {
					return creds, err
				}
			}

			// success!
			return creds, nil
		}
	}

	return creds, keyring.ErrKeyNotFound
}

// Store stores a sessions for a specific profile, expects the source profile to be provided
func (s *KeyringSessions) Store(profile string, session sts.Credentials, expires time.Time) error {
	bytes, err := json.Marshal(session)
	if err != nil {
		return err
	}

	key := fmt.Sprintf("%s session (%d)", profile, expires.Unix())
	log.Printf("Writing session for %s to keyring: %q", profile, key)

	return s.Keyring.Set(keyring.Item{
		Key:         key,
		Label:       "aws-vault session for " + profile,
		Description: "aws-vault session for " + profile,
		Data:        bytes,

		// specific Keychain settings
		KeychainNotTrustApplication: true,
	})
}

// Delete deletes any sessions for a specific profile, expects the source profile to be provided
func (s *KeyringSessions) Delete(profile string) (n int, err error) {
	log.Printf("Looking for sessions for %s", profile)
	sessions, err := s.Sessions()
	if err != nil {
		return n, err
	}

	for _, session := range sessions {
		if session.Profile.Name == profile {
			log.Printf("Session %q matches profile %q", session.Name, profile)
			if err = s.Keyring.Remove(session.Profile.Name); err != nil {
				return n, err
			}
			n++
		}
	}

	return
}
