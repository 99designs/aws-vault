package main

import (
	"flag"
	"log"
	"os"

	"github.com/99designs/aws-vault/Godeps/_workspace/src/github.com/mitchellh/cli"
	"github.com/99designs/aws-vault/command"
	"github.com/99designs/aws-vault/keyring"
)

var (
	Version string
)

func main() {
	ui := &cli.BasicUi{
		Writer: os.Stdout,
		Reader: os.Stdin,
	}

	// handle profile at the top level, I always do this.
	var profile string
	flag.StringVar(&profile, "profile", command.ProfileFromEnv(), "")
	flag.StringVar(&profile, "p", command.ProfileFromEnv(), "")
	flag.Parse()

	// log.Printf("%s %#v",)

	k := keyring.DefaultKeyring
	c := cli.NewCLI("aws-vault", Version)
	c.Args = flag.Args()
	c.Commands = map[string]cli.CommandFactory{
		"store": func() (cli.Command, error) {
			return &command.StoreCommand{
				Ui:             ui,
				Keyring:        k,
				DefaultProfile: profile,
			}, nil
		},
		"rm": func() (cli.Command, error) {
			return &command.RemoveCommand{
				Ui:             ui,
				Keyring:        k,
				DefaultProfile: profile,
			}, nil
		},
		"exec": func() (cli.Command, error) {
			return &command.ExecCommand{
				Ui:             ui,
				Keyring:        k,
				Env:            os.Environ(),
				DefaultProfile: profile,
			}, nil
		},
		"ls": func() (cli.Command, error) {
			return &command.ListCommand{
				Ui:      ui,
				Keyring: k,
			}, nil
		},
	}

	exitStatus, err := c.Run()
	if err != nil {
		log.Println(err)
	}

	os.Exit(exitStatus)
}
