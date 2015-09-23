package main

import (
	"crypto/sha1"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/dvsekhvalnov/jose2go"
)

var sessionVersion = "1"
var defaultSessionStore *sessionStore = newSessionStore(os.Getenv("AWSVAULT_SESSION_DIR"))

type sessionKey struct {
	credentials.Value
	Profile   string
	MFASerial string
}

func (s *sessionKey) String() string {
	return fmt.Sprintf("%x",
		sha1.Sum([]byte(fmt.Sprintf("%s:%s:%s", s.AccessKeyID, s.Profile, s.MFASerial))),
	)
}

type sessionStore struct {
	Dir    string
	create sync.Once
}

func newSessionStore(dir string) *sessionStore {
	return &sessionStore{Dir: dir}
}

func (s *sessionStore) dir() (string, error) {
	dir := s.Dir
	if dir == "" {
		usr, err := user.Current()
		if err != nil {
			return dir, err
		}
		dir = usr.HomeDir + "/.awsvault/sessions/"
	}

	stat, err := os.Stat(dir)
	if os.IsNotExist(err) {
		os.MkdirAll(dir, 0700)
	} else if err != nil && !stat.IsDir() {
		err = fmt.Errorf("%s is a file, not a directory", dir)
	}

	return dir, nil
}

func (s *sessionStore) Get(key sessionKey) (sts.Credentials, error) {
	dir, err := s.dir()
	if err != nil {
		return sts.Credentials{}, err
	}

	bytes, err := ioutil.ReadFile(filepath.Join(dir, key.String()))
	if os.IsNotExist(err) {
		return sts.Credentials{}, errSessionNotFound
	} else if err != nil {
		return sts.Credentials{}, err
	}

	payload, headers, err := jose.Decode(string(bytes), key.SecretAccessKey)
	if err != nil {
		return sts.Credentials{}, err
	}

	expires, err := time.Parse(time.RFC822Z, headers["expires"].(string))
	if err != nil {
		return sts.Credentials{}, err
	}

	if time.Now().After(expires) {
		log.Printf("Found expired session, removing")
		defer s.Remove(key)
		return sts.Credentials{}, errSessionNotFound
	}

	var decoded sts.Credentials
	err = json.Unmarshal([]byte(payload), &decoded)

	return decoded, err
}

func (s *sessionStore) Set(key sessionKey, creds sts.Credentials) error {
	bytes, err := json.Marshal(creds)
	if err != nil {
		return err
	}

	token, err := jose.Encrypt(string(bytes), jose.PBES2_HS256_A128KW, jose.A256GCM, key.SecretAccessKey,
		jose.Headers(map[string]interface{}{
			"keyid":   key.AccessKeyID,
			"version": sessionVersion,
			"expires": creds.Expiration.Format(time.RFC822Z),
		}))
	if err != nil {
		return err
	}

	dir, err := s.dir()
	if err != nil {
		return err
	}

	return ioutil.WriteFile(filepath.Join(dir, key.String()), []byte(token), 0600)
}

func (s *sessionStore) Remove(key sessionKey) error {
	dir, err := s.dir()
	if err != nil {
		return err
	}

	return os.Remove(filepath.Join(dir, key.String()))
}

var errSessionNotFound = errors.New("Session not found")
