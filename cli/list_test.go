package cli

import (
	"github.com/alecthomas/kingpin"

	"github.com/99designs/keyring"
)

func ExampleListCommand() {
	app := kingpin.New("aws-vault", "")
	awsVault := ConfigureGlobals(app)
	awsVault.keyringImpl = keyring.NewArrayKeyring([]keyring.Item{
		{Key: "llamas", Data: []byte(`{"AccessKeyID":"ABC","SecretAccessKey":"XYZ"}`)},
	})
	ConfigureListCommand(app, awsVault)
	kingpin.MustParse(app.Parse([]string{
		"list", "--credentials",
	}))

	// Output:
	// llamas
}
