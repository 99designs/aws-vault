package cli

import (
	"github.com/alecthomas/kingpin"

	"github.com/99designs/keyring"
)

func ExampleExecCommand() {
	app := kingpin.New("aws-vault", "")
	awsVault := ConfigureGlobals(app)
	awsVault.keyringImpl = keyring.NewArrayKeyring([]keyring.Item{
		{Key: "llamas", Data: []byte(`{"AccessKeyID":"ABC","SecretAccessKey":"XYZ"}`)},
	})
	ConfigureExecCommand(app, awsVault)
	kingpin.MustParse(app.Parse([]string{
		"--debug", "exec", "--no-session", "llamas", "--", "sh", "-c", "echo $AWS_ACCESS_KEY_ID",
	}))

	// Output:
	// ABC
}
