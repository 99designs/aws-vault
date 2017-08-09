// +build darwin

package keyring

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	homedir "github.com/mitchellh/go-homedir"
)

var keychainDir string

func deleteKeychain(name string) {
	home, err := homedir.Dir()
	if err != nil {
		panic(err)
	}

	f := filepath.Join(home, "Library/Keychains", name+"-db")
	log.Printf("removing %s", f)

	if err = os.Remove(f); err != nil {
		panic(err)
	}
}

func TestOSXKeychainKeyringSet(t *testing.T) {
	name := tmpKeychain(t)
	defer deleteKeychain(name)

	k := &keychain{
		path:       name,
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
	name := tmpKeychain(t)
	defer deleteKeychain(name)

	k := &keychain{
		path:       name,
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

func tmpKeychain(t *testing.T) (name string) {
	return fmt.Sprintf("aws-vault-test-%d.keychain", time.Now().UnixNano())
}
