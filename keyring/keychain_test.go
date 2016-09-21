// +build darwin

package keyring

import (
	"io/ioutil"
	"os"
	"reflect"
	"testing"
)

func TestOSXKeychainDoesntExist(t *testing.T) {
	file := tmpKeychain(t)
	defer os.Remove(file)

	k, err := createKeychain(file, false, "llamas")
	if err != nil {
		t.Fatal(err)
	}
	defer releaseKeychain(k)

	if exists, _ := keychainExists(file); !exists {
		t.Fatalf("Expected existing keychain to be shown as existing")
	}

	if exists, _ := keychainExists("llamaspleasedontbeakeychainwiththisname"); exists {
		t.Fatalf("Expected non-existing keychain to NOT be shown as existing")
	}
}

func TestOSXKeychainKeyringSet(t *testing.T) {
	file := tmpKeychain(t)
	defer os.Remove(file)

	k := &keychain{path: file, passphrase: "llamas", service: "test"}
	item := Item{
		Key:         "llamas",
		Label:       "Arbitrary label",
		Description: "A freetext description",
		Data:        []byte("llamas are great"),
		TrustSelf:   true,
	}

	if err := k.Set(item); err != nil {
		t.Fatal(err)
	}

	v, err := k.Get("llamas")
	if err != nil {
		t.Fatal(err)
	}

	if string(v.Data) != string(item.Data) {
		t.Fatalf("Data stored was not the data retrieved: %q vs %q", v.Data, item.Data)
	}

	if string(v.Key) != item.Key {
		t.Fatalf("Key stored was not the data retrieved: %q vs %q", v.Key, item.Key)
	}

	if string(v.Description) != item.Description {
		t.Fatalf("Description stored was not the data retrieved: %q vs %q", v.Description, item.Description)
	}
}

func TestOSXKeychainKeyringListKeys(t *testing.T) {
	file := tmpKeychain(t)
	defer os.Remove(file)

	k := &keychain{path: file, passphrase: "llamas", service: "test"}
	keys := []string{"key1", "key2", "key3"}

	for _, key := range keys {
		if err := k.Set(Item{Key: key, Data: []byte("llamas are great")}); err != nil {
			t.Fatal(err)
		}
	}

	keys2, err := k.Keys()
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(keys, keys2) {
		t.Fatalf("Retrieved keys weren't the same: %q vs %q", keys, keys2)
	}
}

func tmpKeychain(t *testing.T) (path string) {
	file, err := ioutil.TempFile(os.TempDir(), "aws-vault-test")
	if err != nil {
		t.Fatal(err)
		return
	}
	os.Remove(file.Name())
	return file.Name()
}
