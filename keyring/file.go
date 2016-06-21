package keyring

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"path/filepath"
	"time"

	jose "github.com/dvsekhvalnov/jose2go"
	"golang.org/x/crypto/ssh/terminal"
)

type passwordFunc func(string) (string, error)

func terminalPrompt(prompt string) (string, error) {
	fmt.Printf("%s: ", prompt)
	b, err := terminal.ReadPassword(1)
	if err != nil {
		return "", err
	}
	fmt.Println()
	return string(b), nil
}

func init() {
	supportedBackends[FileBackend] = opener(func(name string) (Keyring, error) {
		return &fileKeyring{
			PasswordFunc: terminalPrompt,
		}, nil
	})
}

type fileKeyring struct {
	Dir          string
	PasswordFunc passwordFunc
	password     string
}

func (k *fileKeyring) dir() (string, error) {
	dir := k.Dir
	if dir == "" {
		usr, err := user.Current()
		if err != nil {
			return dir, err
		}
		dir = usr.HomeDir + "/.awsvault/keys/"
	}

	stat, err := os.Stat(dir)
	if os.IsNotExist(err) {
		os.MkdirAll(dir, 0700)
	} else if err != nil && !stat.IsDir() {
		err = fmt.Errorf("%s is a file, not a directory", dir)
	}

	return dir, nil
}

func (k *fileKeyring) unlock() error {
	dir, err := k.dir()
	if err != nil {
		return err
	}

	if k.password == "" {
		pwd, err := k.PasswordFunc(fmt.Sprintf("Enter passphrase to unlock %s", dir))
		if err != nil {
			return err
		}
		k.password = pwd
	}

	return nil
}

func (k *fileKeyring) Get(key string) (Item, error) {
	dir, err := k.dir()
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

	dir, err := k.dir()
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
	dir, err := k.dir()
	if err != nil {
		return err
	}

	return os.Remove(filepath.Join(dir, key))
}

func (k *fileKeyring) Keys() ([]string, error) {
	dir, err := k.dir()
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
