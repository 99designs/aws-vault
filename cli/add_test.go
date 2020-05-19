package cli

import (
	"io/ioutil"
	"log"
	"os"

	"github.com/alecthomas/kingpin"
)

func ExampleAddCommand() {
	f, err := ioutil.TempFile("", "aws-config")
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(f.Name())

	os.Setenv("AWS_CONFIG_FILE", f.Name())
	os.Setenv("AWS_ACCESS_KEY_ID", "llamas")
	os.Setenv("AWS_SECRET_ACCESS_KEY", "rock")
	os.Setenv("AWS_VAULT_BACKEND", "file")
	os.Setenv("AWS_VAULT_FILE_PASSPHRASE", "password")

	defer os.Unsetenv("AWS_ACCESS_KEY_ID")
	defer os.Unsetenv("AWS_SECRET_ACCESS_KEY")
	defer os.Unsetenv("AWS_VAULT_BACKEND")
	defer os.Unsetenv("AWS_VAULT_FILE_PASSPHRASE")

	app := kingpin.New(`aws-vault`, ``)
	ConfigureAddCommand(app, ConfigureGlobals(app))
	kingpin.MustParse(app.Parse([]string{"add", "--debug", "--env", "foo"}))

	// Output:
	// Added credentials to profile "foo" in vault
}
