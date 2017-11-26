package keyring

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	jose "github.com/dvsekhvalnov/jose2go"
	homedir "github.com/mitchellh/go-homedir"
)

func init() {
	supportedBackends[FileBackend] = opener(func(cfg Config) (Keyring, error) {
		return &fileKeyring{
			dir:          cfg.FileDir,
			passwordFunc: cfg.FilePasswordFunc,
		}, nil
	})
}

type fileKeyring struct {
	dir          string
	passwordFunc PromptFunc
	password     string
}

func (k *fileKeyring) resolveDir() (string, error) {
	if k.dir == "" {
		return "", fmt.Errorf("No directory provided for file keyring")
	}

	dir := k.dir

	// expand tilde for home directory
	if strings.HasPrefix(dir, "~") {
		home, err := homedir.Dir()
		if err != nil {
			return "", err
		}
		dir = strings.Replace(dir, "~", home, 1)
		debugf("Expanded file dir to %s", dir)
	}

	stat, err := os.Stat(dir)
	if os.IsNotExist(err) {
		err = os.MkdirAll(dir, 0700)
	} else if err != nil && !stat.IsDir() {
		err = fmt.Errorf("%s is a file, not a directory", dir)
	}

	return dir, err
}

func (k *fileKeyring) unlock() error {
	dir, err := k.resolveDir()
	if err != nil {
		return err
	}

	if k.password == "" {
		pwd, err := k.passwordFunc(fmt.Sprintf("Enter passphrase to unlock %s", dir))
		if err != nil {
			return err
		}
		k.password = pwd
	}

	return nil
}

func (k *fileKeyring) Get(key string) (Item, error) {
	dir, err := k.resolveDir()
	if err != nil {
		return Item{}, err
	}

	bytes, err := ioutil.ReadFile(filepath.Join(dir, key))
	if os.IsNotExist(err) {
		return Item{}, ErrKeyNotFound
	} else if err != nil {
		return Item{}, err
	}

	if err = k.unlock(); err != nil {
		return Item{}, err
	}

	payload, _, err := jose.Decode(string(bytes), k.password)
	if err != nil {
		return Item{}, err
	}

	var decoded Item
	err = json.Unmarshal([]byte(payload), &decoded)

	return decoded, err
}

func (k *fileKeyring) Set(i Item) error {
	bytes, err := json.Marshal(i)
	if err != nil {
		return err
	}

	dir, err := k.resolveDir()
	if err != nil {
		return err
	}

	if err = k.unlock(); err != nil {
		return err
	}

	token, err := jose.Encrypt(string(bytes), jose.PBES2_HS256_A128KW, jose.A256GCM, k.password,
		jose.Headers(map[string]interface{}{
			"created": time.Now().String(),
		}))
	if err != nil {
		return err
	}

	return ioutil.WriteFile(filepath.Join(dir, i.Key), []byte(token), 0600)
}

func (k *fileKeyring) Remove(key string) error {
	dir, err := k.resolveDir()
	if err != nil {
		return err
	}

	return os.Remove(filepath.Join(dir, key))
}

func (k *fileKeyring) Keys() ([]string, error) {
	dir, err := k.resolveDir()
	if err != nil {
		return nil, err
	}

	var keys = []string{}
	files, _ := ioutil.ReadDir(dir)
	for _, f := range files {
		keys = append(keys, f.Name())
	}

	return keys, nil
}
