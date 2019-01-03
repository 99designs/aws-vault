// +build darwin,cgo

package keyring

import (
	"fmt"

	gokeychain "github.com/keybase/go-keychain"
)

type keychain struct {
	path    string
	service string

	passwordFunc PromptFunc

	isSynchronizable         bool
	isAccessibleWhenUnlocked bool
	isTrusted                bool
}

func init() {
	supportedBackends[KeychainBackend] = opener(func(cfg Config) (Keyring, error) {
		kc := &keychain{
			service:      cfg.ServiceName,
			passwordFunc: cfg.KeychainPasswordFunc,
		}
		if cfg.KeychainName != "" {
			kc.path = cfg.KeychainName + ".keychain"
		}
		if cfg.KeychainTrustApplication {
			kc.isTrusted = true
		}
		return kc, nil
	})
}

func (k *keychain) Get(key string) (Item, error) {
	query := gokeychain.NewItem()
	query.SetSecClass(gokeychain.SecClassGenericPassword)
	query.SetService(k.service)
	query.SetAccount(key)
	query.SetMatchLimit(gokeychain.MatchLimitOne)
	query.SetReturnAttributes(true)
	query.SetReturnData(true)

	if k.path != "" {
		// When we are querying, we don't create by default
		query.SetMatchSearchList(gokeychain.NewWithPath(k.path))
	}

	debugf("Querying keychain for service=%q, account=%q, keychain=%q", k.service, key, k.path)
	results, err := gokeychain.QueryItem(query)
	if err == gokeychain.ErrorItemNotFound || len(results) == 0 {
		debugf("No results found")
		return Item{}, ErrKeyNotFound
	}

	if err != nil {
		debugf("Error: %#v", err)
		return Item{}, err
	}

	item := Item{
		Key:         key,
		Data:        results[0].Data,
		Label:       results[0].Label,
		Description: results[0].Description,
	}

	debugf("Found item %q", results[0].Label)
	return item, nil
}

func (k *keychain) Set(item Item) error {
	var kc gokeychain.Keychain

	// when we are setting a value, we create or open
	if k.path != "" {
		var err error
		kc, err = k.createOrOpen()
		if err != nil {
			return err
		}
	}

	kcItem := gokeychain.NewItem()
	kcItem.SetSecClass(gokeychain.SecClassGenericPassword)
	kcItem.SetService(k.service)
	kcItem.SetAccount(item.Key)
	kcItem.SetLabel(item.Label)
	kcItem.SetDescription(item.Description)
	kcItem.SetData(item.Data)

	if k.path != "" {
		kcItem.UseKeychain(kc)
	}

	if k.isSynchronizable && !item.KeychainNotSynchronizable {
		kcItem.SetSynchronizable(gokeychain.SynchronizableYes)
	}

	if k.isAccessibleWhenUnlocked {
		kcItem.SetAccessible(gokeychain.AccessibleWhenUnlocked)
	}

	isTrusted := k.isTrusted && !item.KeychainNotTrustApplication

	if isTrusted {
		debugf("Keychain item trusts aws-vault")
		kcItem.SetAccess(&gokeychain.Access{
			Label:               item.Label,
			TrustedApplications: nil,
		})
	} else {
		debugf("Keychain item doesn't trust aws-vault")
		kcItem.SetAccess(&gokeychain.Access{
			Label:               item.Label,
			TrustedApplications: []string{},
		})
	}

	debugf("Adding service=%q, label=%q, account=%q, trusted=%v to osx keychain %q", k.service, item.Label, item.Key, isTrusted, k.path)

	if err := gokeychain.AddItem(kcItem); err == gokeychain.ErrorDuplicateItem {
		debugf("Item already exists, deleting")
		delItem := gokeychain.NewItem()
		delItem.SetSecClass(gokeychain.SecClassGenericPassword)
		delItem.SetService(k.service)
		delItem.SetAccount(item.Key)

		if k.path != "" {
			delItem.SetMatchSearchList(kc)
		}

		if err = gokeychain.DeleteItem(delItem); err != nil {
			return fmt.Errorf("Error deleting existing item: %v", err)
		}

		debugf("Adding item again")
		return gokeychain.AddItem(kcItem)
	}

	return nil
}

func (k *keychain) Remove(key string) error {
	item := gokeychain.NewItem()
	item.SetSecClass(gokeychain.SecClassGenericPassword)
	item.SetService(k.service)
	item.SetAccount(key)

	if k.path != "" {
		kc := gokeychain.NewWithPath(k.path)

		if err := kc.Status(); err != nil {
			return err
		}

		item.SetMatchSearchList(kc)
	}

	debugf("Removing keychain item service=%q, account=%q, keychain %q", k.service, key, k.path)
	return gokeychain.DeleteItem(item)
}

func (k *keychain) Keys() ([]string, error) {
	query := gokeychain.NewItem()
	query.SetSecClass(gokeychain.SecClassGenericPassword)
	query.SetService(k.service)
	query.SetMatchLimit(gokeychain.MatchLimitAll)
	query.SetReturnAttributes(true)

	if k.path != "" {
		kc := gokeychain.NewWithPath(k.path)

		if err := kc.Status(); err != nil {
			return nil, err
		}

		query.SetMatchSearchList(kc)
	}

	debugf("Querying keychain for service=%q, keychain=%q", k.service, k.path)
	results, err := gokeychain.QueryItem(query)
	if err != nil {
		return nil, err
	}

	debugf("Found %d results", len(results))
	accountNames := make([]string, len(results))
	for idx, r := range results {
		accountNames[idx] = r.Account
	}

	return accountNames, nil
}

func (k *keychain) createOrOpen() (gokeychain.Keychain, error) {
	kc := gokeychain.NewWithPath(k.path)

	debugf("Checking keychain status")
	err := kc.Status()
	if err == nil {
		debugf("Keychain status returned nil, keychain exists")
		return kc, nil
	} else {
		debugf("Keychain status returned error: %v", err)
	}

	if err != gokeychain.ErrorNoSuchKeychain {
		return gokeychain.Keychain{}, err
	}

	if k.passwordFunc == nil {
		debugf("Creating keychain %s with prompt", k.path)
		return gokeychain.NewKeychainWithPrompt(k.path)
	}

	passphrase, err := k.passwordFunc("Enter passphrase for keychain")
	if err != nil {
		return gokeychain.Keychain{}, err
	}

	debugf("Creating keychain %s with provided password", k.path)
	return gokeychain.NewKeychain(k.path, passphrase)
}
