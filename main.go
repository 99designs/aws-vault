package main

import (
	"os"

	"github.com/99designs/aws-vault/v6/cli"
	"gopkg.in/alecthomas/kingpin.v2"
)

// Version is provided at compile time
var Version = "dev"

func main() {
	app := kingpin.New("aws-vault", "A vault for securely storing and accessing AWS credentials in development environments.")
	app.Version(Version)

	a := cli.ConfigureGlobals(app)
	cli.ConfigureAddCommand(app, a)
	cli.ConfigureListCommand(app, a)
	cli.ConfigureRotateCommand(app, a)
	cli.ConfigureExecCommand(app, a)
	cli.ConfigureRemoveCommand(app, a)
	cli.ConfigureLoginCommand(app, a)
	cli.ConfigureServerCommand(app, a)
	cli.ConfigureInfoCommand(app, a)

	kingpin.MustParse(app.Parse(os.Args[1:]))
}
