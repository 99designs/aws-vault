// +build darwin
package keyring

import (
	"io/ioutil"
	"os"
	"reflect"
	"testing"
)

func TestOSXKeychainKeyringSetWhenEmpty(t *testing.T) {
	file := tmpKeychain(t)
	defer os.Remove(file)

	k := &OSXKeychain{path: file, password: "llamas", service: "test"}

	if err := k.Set("llamas", []byte("llamas are great")); err != nil {
		t.Fatal(err)
	}

	v, err := k.Get("llamas")
	if err != nil {
		t.Fatal(err)
	}

	if string(v) != "llamas are great" {
		t.Fatalf("Value stored was not the value retrieved: %q", v)
	}
}

func TestOSXKeychainKeyringSetWhenNotEmpty(t *testing.T) {
	file := tmpKeychain(t)
	defer os.Remove(file)

	k := &OSXKeychain{path: file, password: "llamas", service: "test"}

	if err := k.Set("llamas", []byte("llamas are great 1")); err != nil {
		t.Fatal(err)
	}

	if err := k.Set("llamas", []byte("llamas are great 2")); err != nil {
		t.Fatal(err)
	}

	v, err := k.Get("llamas")
	if err != nil {
		t.Fatal(err)
	}

	if string(v) != "llamas are great 2" {
		t.Fatalf("Value stored was not the value retrieved: %q", v)
	}
}

func TestOSXKeychainKeyringListKeys(t *testing.T) {
	file := tmpKeychain(t)
	defer os.Remove(file)

	k := &OSXKeychain{path: file, password: "llamas", service: "test"}
	keys := []string{"key1", "key2", "key3"}

	for _, key := range keys {
		if err := k.Set(key, []byte("llamas are great")); err != nil {
			t.Fatal(err)
		}
	}

	keys2, err := k.Keys()
	if err != nil {
		t.Fatal(err)
	}

	if reflect.DeepEqual(keys, keys2) {
		t.Fatalf("Retrieved keys weren't the same: %q", keys2)
	}
}

func tmpKeychain(t *testing.T) (path string) {
	file, err := ioutil.TempFile(os.TempDir(), "aws-vault-test")
	if err != nil {
		t.Fatal(err)
		return
	}
	os.Remove(file.Name())
	return file.Name() + ".keychain"
}
