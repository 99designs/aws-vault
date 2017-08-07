// +build darwin

package keyring

import (
	"log"

	gokeychain "github.com/keybase/go-keychain"
)

type keychain struct {
	path       string
	service    string
	passphrase string
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
	query.UseKeychain(kc)

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
	kcItem.SetAccess(gokeychain.NoApplicationsTrusted)

	log.Printf("Adding service=%q, account=%q to osx keychain %s", k.service, item.Key, k.path)
	return gokeychain.AddItem(kcItem)
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
	query.UseKeychain(kc)

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

func (k *keychain) createOrOpen() (gokeychain.Keychain, error) {
	kc := gokeychain.NewWithPath(k.path)

	err := kc.Status()
	if err == nil {
		return kc, nil
	}

	if err != gokeychain.ErrorNoSuchKeychain {
		return gokeychain.Keychain{}, err
	}

	if k.passphrase != "" {
		log.Printf("Creating keychain %s with prompt", k.path)
		return gokeychain.NewKeychainWithPrompt(k.path)
	}

	log.Printf("Creating keychain %s with provided password", k.path)
	return gokeychain.NewKeychain(k.path, k.passphrase)
}
