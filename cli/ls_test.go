package cli

import (
	kingpin "gopkg.in/alecthomas/kingpin.v2"

	"github.com/99designs/keyring"
)

func ExampleLsCommand() {
	keyringImpl = keyring.NewArrayKeyring([]keyring.Item{
		{Key: "llamas", Data: []byte(`{"AccessKeyID":"ABC","SecretAccessKey":"XYZ"}`)},
	})

	app := kingpin.New(`aws-vault`, ``)
	ConfigureGlobals(app)
	ConfigureListCommand(app)
	kingpin.MustParse(app.Parse([]string{
		"list", "--credentials",
	}))

	// Output:
	// llamas
}
