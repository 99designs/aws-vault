package main

import (
	"os"

	"github.com/99designs/aws-vault/cli"
	"gopkg.in/alecthomas/kingpin.v2"
)

// Version is provided at compile time
var Version = "dev"

func main() {
	run(os.Args[1:], os.Exit)
}

func run(args []string, exit func(int)) {
	app := kingpin.New(
		`aws-vault`,
		`A vault for securely storing and accessing AWS credentials in development environments.`,
	)

	app.ErrorWriter(os.Stderr)
	app.Writer(os.Stdout)
	app.Version(Version)
	app.Terminate(exit)

	cli.ConfigureGlobals(app)
	cli.ConfigureAddCommand(app)
	cli.ConfigureListCommand(app)
	cli.ConfigureRotateCommand(app)
	cli.ConfigureExecCommand(app)
	cli.ConfigureRemoveCommand(app)
	cli.ConfigureLoginCommand(app)
	cli.ConfigureServerCommand(app)

	kingpin.MustParse(app.Parse(args))
}
