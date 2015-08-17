package keyring

import "testing"

func TestArrayKeyringSetWhenEmpty(t *testing.T) {
	k := &ArrayKeyring{}

	if err := k.Set("test", "llamas", []byte("llamas are great")); err != nil {
		t.Fatal(err)
	}

	v, err := k.Get("test", "llamas")
	if err != nil {
		t.Fatal(err)
	}

	if string(v) != "llamas are great" {
		t.Fatalf("Value stored was not the value retrieved: %q", v)
	}
}
