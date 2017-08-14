// +build linux

package keyring

import (
	"encoding/json"

	"github.com/aulanov/go.dbus"
)

const (
	DBUS_SERVICE_NAME = "org.kde.kwalletd"
	DBUS_PATH         = "/modules/kwalletd"
	APPID             = "aws-vault"
	FOLDER            = "aws-vault"
)

func init() {
	supportedBackends[KWalletBackend] = opener(func(name string) (Keyring, error) {
		if name == "" {
			name = "kdewallet"
		}

		wallet, err := newKwallet()
		if err != nil {
			return nil, err
		}

		return &kwalletKeyring{
			wallet: *wallet,
			name:   name,
		}, nil
	})
}

type kwalletKeyring struct {
	wallet kwalletBinding
	name   string
	handle int32
}

func (k *kwalletKeyring) openWallet() error {
	isOpen, err := k.wallet.IsOpen(k.handle)
	if err != nil {
		return err
	}

	if !isOpen {
		handle, err := k.wallet.Open(k.name, 0, APPID)
		if err != nil {
			return err
		}
		k.handle = handle
	}

	return nil
}

func (k *kwalletKeyring) Get(key string) (Item, error) {
	err := k.openWallet()
	if err != nil {
		return Item{}, err
	}

	data, err := k.wallet.ReadEntry(k.handle, FOLDER, key, APPID)
	if err != nil {
		return Item{}, err
	}

	item := Item{}
	err = json.Unmarshal(data, &item)
	if err != nil {
		return Item{}, err
	}

	return item, nil
}

func (k *kwalletKeyring) Set(item Item) error {
	err := k.openWallet()
	if err != nil {
		return err
	}

	data, err := json.Marshal(item)
	if err != nil {
		return err
	}

	err = k.wallet.WriteEntry(k.handle, FOLDER, item.Key, data, APPID)
	if err != nil {
		return err
	}

	return nil
}

func (k *kwalletKeyring) Remove(key string) error {
	err := k.openWallet()
	if err != nil {
		return err
	}

	err = k.wallet.RemoveEntry(k.handle, FOLDER, key, APPID)
	if err != nil {
		return err
	}

	return nil
}

func (k *kwalletKeyring) Keys() ([]string, error) {
	err := k.openWallet()
	if err != nil {
		return []string{}, err
	}

	entries, err := k.wallet.EntryList(k.handle, FOLDER, APPID)
	if err != nil {
		return []string{}, err
	}

	return entries, nil
}

func newKwallet() (*kwalletBinding, error) {
	conn, err := dbus.SessionBus()
	if err != nil {
		return nil, err
	}

	return &kwalletBinding{
		conn.Object(DBUS_SERVICE_NAME, DBUS_PATH),
	}, nil
}

// Dumb Dbus bindings for kwallet bindings with types
type kwalletBinding struct {
	dbus dbus.BusObject
}

// method bool org.kde.KWallet.isOpen(int handle)
func (k *kwalletBinding) IsOpen(handle int32) (bool, error) {
	call := k.dbus.Call("org.kde.KWallet.isOpen", 0, handle)
	if call.Err != nil {
		return false, call.Err
	}

	return call.Body[0].(bool), call.Err
}

// method int org.kde.KWallet.open(QString wallet, qlonglong wId, QString appid)
func (k *kwalletBinding) Open(name string, wID int64, appid string) (int32, error) {
	call := k.dbus.Call("org.kde.KWallet.open", 0, name, wID, appid)
	if call.Err != nil {
		return 0, call.Err
	}

	return call.Body[0].(int32), call.Err
}

// method QStringList org.kde.KWallet.entryList(int handle, QString folder, QString appid)
func (k *kwalletBinding) EntryList(handle int32, folder string, appid string) ([]string, error) {
	call := k.dbus.Call("org.kde.KWallet.entryList", 0, handle, folder, appid)
	if call.Err != nil {
		return []string{}, call.Err
	}

	return call.Body[0].([]string), call.Err
}

// method int org.kde.KWallet.writeEntry(int handle, QString folder, QString key, QByteArray value, QString appid)
func (k *kwalletBinding) WriteEntry(handle int32, folder string, key string, value []byte, appid string) error {
	call := k.dbus.Call("org.kde.KWallet.writeEntry", 0, handle, folder, key, value, appid)
	if call.Err != nil {
		return call.Err
	}

	return call.Err
}

// method int org.kde.KWallet.removeEntry(int handle, QString folder, QString key, QString appid)
func (k *kwalletBinding) RemoveEntry(handle int32, folder string, key string, appid string) error {
	call := k.dbus.Call("org.kde.KWallet.removeEntry", 0, handle, folder, key, appid)
	if call.Err != nil {
		return call.Err
	}

	return call.Err
}

// method QByteArray org.kde.KWallet.readEntry(int handle, QString folder, QString key, QString appid)
func (k *kwalletBinding) ReadEntry(handle int32, folder string, key string, appid string) ([]byte, error) {
	call := k.dbus.Call("org.kde.KWallet.readEntry", 0, handle, folder, key, appid)
	if call.Err != nil {
		return []byte{}, call.Err
	}

	return call.Body[0].([]byte), call.Err
}
