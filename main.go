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
		debug            = kingpin.Flag("debug", "Show debugging output").Bool()
		add              = kingpin.Command("add", "Adds credentials, prompts if none provided")
		addProfile       = add.Arg("profile", "Name of the profile").Required().String()
		addFromEnv       = add.Flag("env", "Read the credentials from the environment").Bool()
		ls               = kingpin.Command("ls", "List profiles")
		exec             = kingpin.Command("exec", "Executes a command with AWS credentials in the environment")
		execProfile      = exec.Arg("profile", "Name of the profile").Required().String()
		execSessDuration = exec.Flag("session-ttl", "Expiration time for aws session").Default("1h").OverrideDefaultFromEnvar("AWS_SESSION_TTL").Short('t').Duration()
		execCmd          = exec.Arg("cmd", "Command to execute").Default(os.Getenv("SHELL")).String()
		execCmdArgs      = exec.Arg("args", "Command arguments").Strings()
		rm               = kingpin.Command("rm", "Removes credentials")
		rmProfile        = rm.Arg("profile", "Name of the profile").Required().String()
		login            = kingpin.Command("login", "Generate a login link for the AWS Console")
		loginProfile     = login.Arg("profile", "Name of the profile").Required().String()
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

	keyring, err := keyring.ForPlatform()
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
			FromEnv: *addFromEnv,
		})

	case exec.FullCommand():
		ExecCommand(ui, ExecCommandInput{
			Profile:  *execProfile,
			Command:  *execCmd,
			Args:     *execCmdArgs,
			Keyring:  keyring,
			Duration: *execSessDuration,
		})

	case login.FullCommand():
		LoginCommand(ui, LoginCommandInput{
			Profile: *loginProfile,
			Keyring: keyring,
		})
	}

}
