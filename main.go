package main

import (
	"io/ioutil"
	"log"
	"os"

	"github.com/99designs/aws-vault/keyring"

	"gopkg.in/alecthomas/kingpin.v2"
)

var (
	Version string
)

type Ui struct {
	*log.Logger
	Error, Debug *log.Logger
	Exit         func(code int)
}

type logWriter struct{ *log.Logger }

func (w logWriter) Write(b []byte) (int, error) {
	w.Printf("%s", b)
	return len(b), nil
}

func main() {
	var (
		debug       = kingpin.Flag("debug", "Show debugging output").Bool()
		add         = kingpin.Command("add", "Adds credentials")
		addProfile  = add.Arg("profile", "Name of the profile").Required().String()
		ls          = kingpin.Command("ls", "List profiles")
		exec        = kingpin.Command("exec", "Executes a command with AWS credentials in the environment")
		execProfile = exec.Arg("profile", "Name of the profile").Required().String()
		execCmd     = exec.Arg("cmd", "Command to execute").Required().String()
		execCmdArgs = exec.Arg("args", "Command arguments").Strings()
		rm          = kingpin.Command("rm", "Removes credentials")
		rmProfile   = rm.Arg("profile", "Name of the profile").Required().String()
	)

	kingpin.Version(Version)
	kingpin.CommandLine.Help =
		`A vault for securely storing and accessing AWS credentials in development environments.`

	ui := Ui{
		Logger: log.New(os.Stdout, "", 0),
		Error:  log.New(os.Stderr, "", 0),
		Debug:  log.New(ioutil.Discard, "", 0),
		Exit:   os.Exit,
	}

	keyring, err := keyring.DefaultKeyring()
	if err != nil {
		ui.Error.Fatal(err)
	}

	cmd := kingpin.Parse()

	if *debug {
		ui.Debug = log.New(os.Stderr, "DEBUG ", log.LstdFlags)
		log.SetFlags(0)
		log.SetOutput(&logWriter{ui.Debug})
	} else {
		log.SetOutput(ioutil.Discard)
	}

	switch cmd {
	case ls.FullCommand():
		LsCommand(ui, LsCommandInput{
			Keyring: keyring,
		})

	case rm.FullCommand():
		RemoveCommand(ui, RemoveCommandInput{
			Profile: *rmProfile,
			Keyring: keyring,
		})

	case add.FullCommand():
		AddCommand(ui, AddCommandInput{
			Profile: *addProfile,
			Keyring: keyring,
		})

	case exec.FullCommand():
		ExecCommand(ui, ExecCommandInput{
			Profile: *execProfile,
			Command: *execCmd,
			Args:    *execCmdArgs,
			Keyring: keyring,
		})
	}
}
