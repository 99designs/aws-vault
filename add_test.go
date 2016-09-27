package main

import "os"

func ExampleAddCommand() {
	os.Setenv("AWS_ACCESS_KEY_ID", "llamas")
	os.Setenv("AWS_SECRET_ACCESS_KEY", "rock")
	os.Setenv("AWS_VAULT_BACKEND", "file")
	os.Setenv("AWS_VAULT_FILE_PASSPHRASE", "password")

	defer os.Unsetenv("AWS_ACCESS_KEY_ID")
	defer os.Unsetenv("AWS_SECRET_ACCESS_KEY")
	defer os.Unsetenv("AWS_VAULT_BACKEND")
	defer os.Unsetenv("AWS_VAULT_FILE_PASSPHRASE")

	run([]string{"add", "--env", "foo"}, os.Exit)
	// Output:
	// Added credentials to profile "foo" in vault
}
