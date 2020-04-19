package cli

import (
	"github.com/99designs/aws-vault/server"
	kingpin "gopkg.in/alecthomas/kingpin.v2"
)

type ServerCommandInput struct {
}

func ConfigureServerCommand(app *kingpin.Application) {
	input := ServerCommandInput{}

	cmd := app.Command("server", "Run an ec2 instance role server locally").
		Hidden()

	cmd.Action(func(c *kingpin.ParseContext) error {
		ServerCommand(app, input)
		return nil
	})
}

func ServerCommand(app *kingpin.Application, input ServerCommandInput) {
	if err := server.StartEc2MetadataEndpointProxy(); err != nil {
		app.Fatalf("Server failed: %v", err)
	}
}
