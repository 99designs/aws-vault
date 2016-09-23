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

const (
	KeyringName = "aws-vault"
)

var (
	Version string

	keyringImpl       keyring.Keyring
	promptsAvailable  = prompt.Available()
	backendsAvailable = keyring.SupportedBackends()
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

type globalFlags struct {
	Debug        bool
	Backend      string
	PromptDriver string
}

func configureAddCommand(app *kingpin.Application, ui Ui, g *globalFlags) {
	input := AddCommandInput{}

	cmd := app.Command("add", "Adds credentials, prompts if none provided")
	cmd.Arg("profile", "Name of the profile").
		Required().
		StringVar(&input.Profile)

	cmd.Flag("env", "Read the credentials from the environment").
		BoolVar(&input.FromEnv)

	cmd.Action(func(c *kingpin.ParseContext) error {
		input.Keyring = keyringImpl
		AddCommand(ui, input)
		return nil
	})
}

func configureListCommand(app *kingpin.Application, ui Ui, g *globalFlags) {
	input := LsCommandInput{}

	cmd := app.Command("ls", "List profiles")
	cmd.Action(func(c *kingpin.ParseContext) error {
		input.Keyring = keyringImpl
		LsCommand(ui, input)
		return nil
	})
}

func configureRotateCommand(app *kingpin.Application, ui Ui, g *globalFlags) {
	input := RotateCommandInput{}

	cmd := app.Command("rotate", "Rotates credentials")
	cmd.Arg("profile", "Name of the profile").
		Required().
		StringVar(&input.Profile)

	cmd.Flag("mfa-token", "The mfa token to use").
		Short('t').
		StringVar(&input.MfaToken)

	cmd.Action(func(c *kingpin.ParseContext) error {
		input.MfaPrompt = prompt.Method(g.PromptDriver)
		input.Keyring = keyringImpl
		RotateCommand(ui, input)
		return nil
	})
}

func configureExecCommand(app *kingpin.Application, ui Ui, g *globalFlags) {
	input := ExecCommandInput{}

	cmd := app.Command("exec", "Executes a command with AWS credentials in the environment")
	cmd.Flag("no-session", "Use root credentials, no session created").
		Short('n').
		BoolVar(&input.NoSession)

	cmd.Flag("session-ttl", "Expiration time for aws session").
		Default("4h").
		OverrideDefaultFromEnvar("AWS_SESSION_TTL").
		Short('t').
		DurationVar(&input.Duration)

	cmd.Flag("assume-role-ttl", "Expiration time for aws assumed role").
		Default("15m").
		DurationVar(&input.RoleDuration)

	cmd.Flag("mfa-token", "The mfa token to use").
		Short('m').
		StringVar(&input.MfaToken)

	cmd.Flag("server", "Run the server in the background for credentials").
		Short('s').
		BoolVar(&input.StartServer)

	cmd.Arg("profile", "Name of the profile").
		Required().
		StringVar(&input.Profile)

	cmd.Arg("cmd", "Command to execute").
		Default(os.Getenv("SHELL")).
		StringVar(&input.Command)

	cmd.Arg("args", "Command arguments").
		StringsVar(&input.Args)

	cmd.Action(func(c *kingpin.ParseContext) error {
		input.Keyring = keyringImpl
		input.MfaPrompt = prompt.Method(g.PromptDriver)
		input.Signals = make(chan os.Signal)
		signal.Notify(input.Signals, os.Interrupt, os.Kill)
		ExecCommand(ui, input)
		return nil
	})
}

func configureRemoveCommand(app *kingpin.Application, ui Ui, g *globalFlags) {
	input := RemoveCommandInput{}

	cmd := app.Command("rm", "Removes credentials, including sessions")
	cmd.Arg("profile", "Name of the profile").
		Required().
		StringVar(&input.Profile)

	cmd.Flag("sessions-only", "Only remove sessions, leave credentials intact").
		Short('s').
		BoolVar(&input.SessionsOnly)

	cmd.Action(func(c *kingpin.ParseContext) error {
		input.Keyring = keyringImpl
		RemoveCommand(ui, input)
		return nil
	})
}

func configureLoginCommand(app *kingpin.Application, ui Ui, g *globalFlags) {
	input := LoginCommandInput{}

	cmd := app.Command("login", "Generate a login link for the AWS Console")
	cmd.Arg("profile", "Name of the profile").
		Required().
		StringVar(&input.Profile)

	cmd.Flag("mfa-token", "The mfa token to use").
		Short('t').
		StringVar(&input.MfaToken)

	cmd.Flag("federation-token-ttl", "Expiration time for aws console session").
		Default("12h").
		OverrideDefaultFromEnvar("AWS_FEDERATION_TOKEN_TTL").
		Short('f').
		DurationVar(&input.FederationTokenDuration)

	cmd.Flag("assume-role-ttl", "Expiration time for aws assumed role").
		Default("15m").
		DurationVar(&input.AssumeRoleDuration)

	cmd.Flag("stdout", "Print login URL to stdout instead of opening in default browser").
		Short('s').
		BoolVar(&input.UseStdout)

	cmd.Action(func(c *kingpin.ParseContext) error {
		input.MfaPrompt = prompt.Method(g.PromptDriver)
		input.Keyring = keyringImpl
		LoginCommand(ui, input)
		return nil
	})
}

func configureServerCommand(app *kingpin.Application, ui Ui, g *globalFlags) {
	input := ServerCommandInput{}

	cmd := app.Command("server", "Run an ec2 instance role server locally")
	cmd.Action(func(c *kingpin.ParseContext) error {
		ServerCommand(ui, input)
		return nil
	})
}

func main() {
	ui := Ui{
		Logger: log.New(os.Stdout, "", 0),
		Error:  log.New(os.Stderr, "", 0),
		Debug:  log.New(ioutil.Discard, "", 0),
		Exit:   os.Exit,
	}

	app := kingpin.New("aws-vault",
		`A vault for securely storing and accessing AWS credentials in development environments.`)

	globals := &globalFlags{}

	app.Version(Version)
	app.Writer(os.Stdout)

	app.Flag("debug", "Show debugging output").
		BoolVar(&globals.Debug)

	app.Flag("backend", fmt.Sprintf("Secret backend to use %v", backendsAvailable)).
		Default(keyring.DefaultBackend).
		OverrideDefaultFromEnvar("AWS_VAULT_BACKEND").
		EnumVar(&globals.Backend, backendsAvailable...)

	app.Flag("prompt", fmt.Sprintf("Prompt driver to use %v", promptsAvailable)).
		Default("terminal").
		OverrideDefaultFromEnvar("AWS_VAULT_PROMPT").
		EnumVar(&globals.PromptDriver, promptsAvailable...)

	app.PreAction(func(c *kingpin.ParseContext) (err error) {
		keyringImpl, err = keyring.Open(KeyringName, globals.Backend)
		return err
	})

	configureAddCommand(app, ui, globals)
	configureListCommand(app, ui, globals)
	configureRotateCommand(app, ui, globals)
	configureExecCommand(app, ui, globals)
	configureRemoveCommand(app, ui, globals)
	configureLoginCommand(app, ui, globals)
	configureServerCommand(app, ui, globals)

	kingpin.MustParse(app.Parse(os.Args[1:]))

	if globals.Debug {
		ui.Debug = log.New(os.Stderr, "DEBUG ", log.LstdFlags)
		log.SetFlags(0)
		log.SetOutput(&logWriter{ui.Debug})
	} else {
		log.SetOutput(ioutil.Discard)
	}
}
