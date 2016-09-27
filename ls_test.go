package main

import (
	"os"

	"github.com/99designs/aws-vault/keyring"
)

func ExampleListCommand() {
	keyringImpl = keyring.NewArrayKeyring([]keyring.Item{
		{Key: "llamas", Data: []byte(`{"AccessKeyID":"ABC","SecretAccessKey":"XYZ"}`)},
	})

	run([]string{"list"}, os.Exit)
	// Output:
	// llamas
}
