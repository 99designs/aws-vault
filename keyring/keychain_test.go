// +build darwin

package keyring

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestOSXKeychainKeyringSet(t *testing.T) {
	path := tempPath()
	defer deleteKeychain(path, t)

	k := &keychain{
		path:       path,
		passphrase: "llamas",
		service:    "test",
	}

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
	path := tempPath()
	defer deleteKeychain(path, t)

	k := &keychain{
		path:       path,
		passphrase: "llamas",
		service:    "test",
	}

	keys := []string{"key1", "key2", "key3"}

	for _, key := range keys {
		item := Item{
			Key:       key,
			Data:      []byte("llamas are great"),
			TrustSelf: true,
		}

		if err := k.Set(item); err != nil {
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

func deleteKeychain(path string, t *testing.T) {
	if _, err := os.Stat(path); os.IsExist(err) {
		t.Logf("Deleting %s", path)
		os.Remove(path)
	}

	// Sierra introduced a -db suffix
	dbPath := path + "-db"
	if _, err := os.Stat(dbPath); os.IsExist(err) {
		t.Logf("Deleting %s", dbPath)
		os.Remove(dbPath)
	}
}

func tempPath() string {
	return filepath.Join(os.TempDir(), fmt.Sprintf("aws-vault-test-%d.keychain", time.Now().UnixNano()))
}
