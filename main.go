package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/signal"

	"github.com/99designs/aws-vault/keyring"
	"github.com/99designs/aws-vault/prompt"
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
		prompts          = prompt.Available()
		debug            = kingpin.Flag("debug", "Show debugging output").Bool()
		add              = kingpin.Command("add", "Adds credentials, prompts if none provided")
		addProfile       = add.Arg("profile", "Name of the profile").Required().String()
		addFromEnv       = add.Flag("env", "Read the credentials from the environment").Bool()
		ls               = kingpin.Command("ls", "List profiles")
		exec             = kingpin.Command("exec", "Executes a command with AWS credentials in the environment")
		execProfile      = exec.Arg("profile", "Name of the profile").Required().String()
		execSessDuration = exec.Flag("session-ttl", "Expiration time for aws session").Default("4h").OverrideDefaultFromEnvar("AWS_SESSION_TTL").Short('t').Duration()
		execMfaToken     = exec.Flag("mfa-token", "The mfa token to use").Short('m').String()
		execMfaPrompt    = exec.Flag("mfa-prompt", fmt.Sprintf("Prompt to use for mfa, from %v", prompts)).Default("terminal").OverrideDefaultFromEnvar("AWS_VAULT_PROMPT").Enum(prompts...)
		execServer       = exec.Flag("server", "Run the server in the background for credentials").Short('s').Bool()
		execCmd          = exec.Arg("cmd", "Command to execute").Default(os.Getenv("SHELL")).String()
		execCmdArgs      = exec.Arg("args", "Command arguments").Strings()
		rm               = kingpin.Command("rm", "Removes credentials, including sessions")
		rmProfile        = rm.Arg("profile", "Name of the profile").Required().String()
		rmSessionsOnly   = rm.Flag("sessions-only", "Only remove sessions, leave credentials intact").Short('s').Bool()
		login            = kingpin.Command("login", "Generate a login link for the AWS Console")
		loginProfile     = login.Arg("profile", "Name of the profile").Required().String()
		loginMfaToken    = login.Flag("mfa-token", "The mfa token to use").Short('t').String()
		loginMfaPrompt   = login.Flag("mfa-prompt", fmt.Sprintf("Prompt to use for mfa, from %v", prompts)).Default("terminal").OverrideDefaultFromEnvar("AWS_VAULT_PROMPT").Enum(prompts...)
		server           = kingpin.Command("server", "Run an ec2 instance role server locally")
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

	keyring, err := keyring.Open("aws-vault")
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
			Profile:      *rmProfile,
			Keyring:      keyring,
			SessionsOnly: *rmSessionsOnly,
		})

	case add.FullCommand():
		AddCommand(ui, AddCommandInput{
			Profile: *addProfile,
			Keyring: keyring,
			FromEnv: *addFromEnv,
		})

	case exec.FullCommand():
		signals := make(chan os.Signal)
		signal.Notify(signals, os.Interrupt, os.Kill)

		ExecCommand(ui, ExecCommandInput{
			Profile:     *execProfile,
			Command:     *execCmd,
			Args:        *execCmdArgs,
			Keyring:     keyring,
			Duration:    *execSessDuration,
			Signals:     signals,
			MfaToken:    *execMfaToken,
			MfaPrompt:   prompt.Method(*execMfaPrompt),
			StartServer: *execServer,
		})

	case login.FullCommand():
		LoginCommand(ui, LoginCommandInput{
			Profile:   *loginProfile,
			Keyring:   keyring,
			MfaToken:  *loginMfaToken,
			MfaPrompt: prompt.Method(*loginMfaPrompt),
		})

	case server.FullCommand():
		ServerCommand(ui, ServerCommandInput{})
	}
}
