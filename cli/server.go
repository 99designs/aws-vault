package cli

import (
	"github.com/99designs/aws-vault/server"
	kingpin "gopkg.in/alecthomas/kingpin.v2"
)

type ServerCommandInput struct {
	Region string
}

func ConfigureServerCommand(app *kingpin.Application) {
	input := ServerCommandInput{}

	cmd := app.Command("server", "Run an ec2 instance role server locally")

	cmd.Arg("region", "The AWS Region (eg: us-east-1) that the metadata server should report").
		Default("us-east-1").
		StringVar(&input.Region)

	cmd.Action(func(c *kingpin.ParseContext) error {
		ServerCommand(app, input)
		return nil
	})
}

func ServerCommand(app *kingpin.Application, input ServerCommandInput) {
	if err := server.StartMetadataServer(input.Region); err != nil {
		app.Fatalf("Server failed: %v", err)
	}
}
