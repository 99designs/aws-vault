package main

import (
	"io/ioutil"
	"log"
	"os"

	"github.com/99designs/aws-vault/Godeps/_workspace/src/github.com/mitchellh/cli"
	"github.com/99designs/aws-vault/command"
)

var (
	Version string
)

func main() {
	if os.Getenv("DEBUG") != "1" {
		log.SetOutput(ioutil.Discard)
	}

	ui := &cli.BasicUi{
		Writer:      os.Stdout,
		Reader:      os.Stdin,
		ErrorWriter: os.Stderr,
	}

	c := cli.NewCLI("aws-vault", Version)
	c.Args = os.Args[1:]
	c.Commands = map[string]cli.CommandFactory{
		"store": func() (cli.Command, error) {
			return &command.StoreCommand{
				Ui: ui,
			}, nil
		},
		"rm": func() (cli.Command, error) {
			return &command.RemoveCommand{
				Ui: ui,
			}, nil
		},
		"exec": func() (cli.Command, error) {
			return &command.ExecCommand{
				Ui: ui,
			}, nil
		},
		"ls": func() (cli.Command, error) {
			return &command.ListCommand{
				Ui: ui,
			}, nil
		},
	}

	exitStatus, err := c.Run()
	if err != nil {
		log.Println(err)
	}

	os.Exit(exitStatus)
}
