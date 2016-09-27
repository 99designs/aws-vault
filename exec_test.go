package main

import (
	"os"

	"github.com/99designs/aws-vault/keyring"
)

func ExampleExecCommand() {
	awsConfigFile = &fileConfig{}
	keyringImpl = keyring.NewArrayKeyring([]keyring.Item{
		{Key: "llamas", Data: []byte(`{"AccessKeyID":"ABC","SecretAccessKey":"XYZ"}`)},
	})

	run([]string{"--debug", "exec", "--no-session", "llamas", "--", "sh", "-c", "echo $AWS_ACCESS_KEY_ID"}, os.Exit)
	// Output:
	// ABC
}
