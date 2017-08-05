// +build darwin

package keyring

import (
	"errors"
	"fmt"
	"log"
	"os"

	"golang.org/x/crypto/ssh/terminal"

	gokeychain "github.com/keybase/go-keychain"
	touchid "github.com/lox/go-touchid"
)

const (
	keychainAccessGroup = "ACE1234DEF.com.99designs.aws-vault"
	biometricsAccount   = "com.99designs.aws-vault.biometrics"
	biometricsService   = "aws-vault"
	biometricsLabel     = "Passphrase for %s"
)

type keychain struct {
	path          string
	service       string
	passphrase    string
	authenticated bool
}

func init() {
	supportedBackends[KeychainBackend] = opener(func(name string) (Keyring, error) {
		if name == "" {
			name = "login"
		}

		return &keychain{
			service: name,
			path:    name + ".keychain",
		}, nil
	})

	DefaultBackend = KeychainBackend
}

func (k *keychain) Get(key string) (Item, error) {
	kc, err := k.createOrOpen()
	if err != nil {
		return Item{}, err
	}

	query := gokeychain.NewItem()
	query.SetSecClass(gokeychain.SecClassGenericPassword)
	query.SetService(k.service)
	query.SetAccount(key)
	query.SetMatchLimit(gokeychain.MatchLimitOne)
	query.SetReturnAttributes(true)
	query.SetReturnData(true)
	query.SetMatchSearchList(kc)

	log.Printf("Querying service=%q, account=%q in osx keychain %s", k.service, key, k.path)
	results, err := gokeychain.QueryItem(query)
	if err == gokeychain.ErrorItemNotFound || len(results) == 0 {
		return Item{}, ErrKeyNotFound
	}

	if err != nil {
		return Item{}, err
	}

	item := Item{
		Key:         key,
		Data:        results[0].Data,
		Label:       results[0].Label,
		Description: results[0].Description,
	}

	return item, nil
}

func (k *keychain) Set(item Item) error {
	kc, err := k.createOrOpen()
	if err != nil {
		return err
	}

	kcItem := gokeychain.NewItem()
	kcItem.SetSecClass(gokeychain.SecClassGenericPassword)
	kcItem.SetService(k.service)
	kcItem.SetAccount(item.Key)
	kcItem.SetLabel(item.Label)
	kcItem.SetDescription(item.Description)
	kcItem.SetData(item.Data)
	kcItem.SetSynchronizable(gokeychain.SynchronizableNo)
	kcItem.SetAccessible(gokeychain.AccessibleWhenUnlocked)
	kcItem.UseKeychain(kc)
	kcItem.SetAccess(&gokeychain.Access{SelfUntrusted: !item.TrustSelf})

	log.Printf("Adding service=%q, label=%q, account=%q to osx keychain %s", k.service, item.Label, item.Key, k.path)
	if err := gokeychain.AddItem(kcItem); err == gokeychain.ErrorDuplicateItem {
		log.Printf("Item already exists, deleting")
		delItem := gokeychain.NewItem()
		delItem.SetSecClass(gokeychain.SecClassGenericPassword)
		delItem.SetService(k.service)
		delItem.SetAccount(item.Key)
		delItem.SetMatchSearchList(kc)

		if err = gokeychain.DeleteItem(delItem); err != nil {
			return fmt.Errorf("Error deleting existing item: %v", err)
		}

		return gokeychain.AddItem(kcItem)
	}

	return nil
}

func (k *keychain) Remove(key string) error {
	kc := gokeychain.NewWithPath(k.path)

	if err := kc.Status(); err != nil {
		return err
	}

	item := gokeychain.NewItem()
	item.SetSecClass(gokeychain.SecClassGenericPassword)
	item.SetService(k.service)
	item.SetAccount(key)
	item.SetMatchSearchList(kc)

	log.Printf("Removing keychain item service=%q, account=%q from osx keychain %q", k.service, key, k.path)
	return gokeychain.DeleteItem(item)
}

func (k *keychain) Keys() ([]string, error) {
	kc := gokeychain.NewWithPath(k.path)

	if err := kc.Status(); err != nil {
		return nil, err
	}

	query := gokeychain.NewItem()
	query.SetSecClass(gokeychain.SecClassGenericPassword)
	query.SetService(k.service)
	query.SetMatchLimit(gokeychain.MatchLimitAll)
	query.SetReturnAttributes(true)
	query.SetMatchSearchList(kc)

	results, err := gokeychain.QueryItem(query)
	if err != nil {
		return nil, err
	}

	accountNames := make([]string, len(results))
	for idx, r := range results {
		accountNames[idx] = r.Account
	}

	return accountNames, nil
}

func (k *keychain) setupBiometrics() error {
	fmt.Println("\nTo use biometrics for authentication, your keychain password needs to be stored in your login keychain.\n" +
		"You will be prompted for your password.\n")

	fmt.Printf("Password for %q: ", k.path)
	passphrase, err := terminal.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return err
	}

	fmt.Println()

	// needs to be locked first in-case it's already unlocked. if so, an incorrect password can be stored
	log.Printf("Locking keychain %s", k.path)
	gokeychain.LockAtPath(k.path)

	log.Printf("Unlocking keychain %s", k.path)
	if err := gokeychain.UnlockAtPath(k.path, string(passphrase)); err != nil {
		return err
	}

	k.passphrase = string(passphrase)

	item := gokeychain.NewItem()
	item.SetSecClass(gokeychain.SecClassGenericPassword)
	item.SetService(biometricsService)
	item.SetAccount(biometricsAccount)
	item.SetLabel(fmt.Sprintf(biometricsLabel, k.path))
	item.SetData(passphrase)
	item.SetSynchronizable(gokeychain.SynchronizableNo)
	item.SetAccessible(gokeychain.AccessibleWhenUnlocked)

	log.Printf("Adding service=%q, account=%q to osx keychain %s", biometricsService, biometricsAccount, k.path)
	return gokeychain.AddItem(item)
}

func (k *keychain) openWithBiometrics() (gokeychain.Keychain, error) {
	if !k.authenticated {
		log.Printf("Checking touchid")
		ok, err := touchid.Authenticate("unlock " + k.path)
		if !ok || err != nil {
			return gokeychain.Keychain{}, errors.New("Authentication with biometrics failed")
		}

		k.authenticated = true

		log.Printf("Looking up password stored in login.keychain")
		query := gokeychain.NewItem()
		query.SetSecClass(gokeychain.SecClassGenericPassword)
		query.SetService(biometricsService)
		query.SetAccount(biometricsAccount)
		query.SetLabel(fmt.Sprintf(biometricsLabel, k.path))
		query.SetMatchLimit(gokeychain.MatchLimitOne)
		query.SetReturnData(true)

		results, err := gokeychain.QueryItem(query)
		if err != nil {
			return gokeychain.Keychain{}, err
		}

		if len(results) != 1 {
			err := k.setupBiometrics()
			if err != nil {
				return gokeychain.Keychain{}, err
			}
		} else {
			log.Printf("Found passphrase in login.keychain, unlocking %s with stored password", k.path)
			if err = gokeychain.UnlockAtPath(k.path, string(results[0].Data)); err != nil {
				return gokeychain.Keychain{}, err
			}
			k.passphrase = string(results[0].Data)
		}
	}

	return gokeychain.NewWithPath(k.path), nil
}

func (k *keychain) createOrOpen() (gokeychain.Keychain, error) {
	kc := gokeychain.NewWithPath(k.path)

	err := kc.Status()
	if err == nil {
		if Config.UseBiometrics {
			log.Printf("Opening %s with biometrics", k.path)
			return k.openWithBiometrics()
		}
		return kc, nil
	}

	if err != gokeychain.ErrorNoSuchKeychain {
		return gokeychain.Keychain{}, err
	}

	if k.passphrase == "" {
		log.Printf("Creating keychain %s with prompt", k.path)
		return gokeychain.NewKeychainWithPrompt(k.path)
	}

	log.Printf("Creating keychain %s with provided password", k.path)
	return gokeychain.NewKeychain(k.path, k.passphrase)
}
