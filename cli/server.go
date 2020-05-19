package cli

import (
	"github.com/99designs/aws-vault/v6/server"
	"github.com/alecthomas/kingpin"
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
