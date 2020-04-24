package cli

import (
	"github.com/99designs/aws-vault/server"
	kingpin "gopkg.in/alecthomas/kingpin.v2"
)

func ConfigureServerCommand(app *kingpin.Application, a *AwsVault) {
	cmd := app.Command("server", "Run an ec2 instance role server locally").
		Hidden()

	cmd.Action(func(c *kingpin.ParseContext) error {
		err := server.StartEc2MetadataEndpointProxy()
		app.FatalIfError(err, "server")
		return nil
	})
}
