package cli

import (
	"log"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/99designs/aws-vault/prompt"
	"github.com/99designs/aws-vault/server"
	"github.com/99designs/aws-vault/vault"
	"github.com/99designs/keyring"
	"gopkg.in/alecthomas/kingpin.v2"
)

type ExecCommandInput struct {
	Profile      string
	Command      string
	Args         []string
	Keyring      keyring.Keyring
	Duration     time.Duration
	RoleDuration time.Duration
	MfaToken     string
	MfaPrompt    prompt.PromptFunc
	StartServer  bool
	Signals      chan os.Signal
	NoSession    bool
}

func ConfigureExecCommand(app *kingpin.Application) {
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
		OverrideDefaultFromEnvar("AWS_ASSUME_ROLE_TTL").
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
		input.MfaPrompt = prompt.Method(GlobalFlags.PromptDriver)
		input.Signals = make(chan os.Signal)
		signal.Notify(input.Signals, os.Interrupt, os.Kill)
		ExecCommand(app, input)
		return nil
	})
}

func ExecCommand(app *kingpin.Application, input ExecCommandInput) {
	if os.Getenv("AWS_VAULT") != "" {
		app.Fatalf("aws-vault sessions should be nested with care, unset $AWS_VAULT to force")
		return
	}

	var setEnv = true

	if input.NoSession && input.StartServer {
		app.Fatalf("Can't start a credential server without a session")
		return
	}

	profiles, err := awsConfigFile.Parse()
	if err != nil {
		app.Fatalf("Error parsing config: %v", err)
		return
	}

	creds, err := vault.NewVaultCredentials(input.Keyring, input.Profile, vault.VaultOptions{
		SessionDuration:    input.Duration,
		AssumeRoleDuration: input.RoleDuration,
		MfaToken:           input.MfaToken,
		MfaPrompt:          input.MfaPrompt,
		NoSession:          input.NoSession,
		Profiles:           profiles,
	})
	if err != nil {
		app.Fatalf("%v", err)
	}

	val, err := creds.Get()
	if err != nil {
		app.Fatalf(vault.FormatCredentialError(input.Profile, profiles, err))
		return
	}

	if input.StartServer {
		if err := server.StartCredentialsServer(creds); err != nil {
			app.Fatalf("Failed to start credential server: %v", err)
		} else {
			setEnv = false
		}
	}

	profs, err := awsConfigFile.Parse()
	if err != nil {
		app.Fatalf("%v", err)
		return
	}

	env := environ(os.Environ())
	env.Set("AWS_VAULT", input.Profile)

	env.Unset("AWS_ACCESS_KEY_ID")
	env.Unset("AWS_SECRET_ACCESS_KEY")
	env.Unset("AWS_CREDENTIAL_FILE")
	env.Unset("AWS_DEFAULT_PROFILE")
	env.Unset("AWS_PROFILE")

	if region, ok := profs[input.Profile]["region"]; ok {
		log.Printf("Setting subprocess env: AWS_DEFAULT_REGION=%s, AWS_REGION=%s", region, region)
		env.Set("AWS_DEFAULT_REGION", region)
		env.Set("AWS_REGION", region)
	}

	if setEnv {
		log.Println("Setting subprocess env: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY")
		env.Set("AWS_ACCESS_KEY_ID", val.AccessKeyID)
		env.Set("AWS_SECRET_ACCESS_KEY", val.SecretAccessKey)

		if val.SessionToken != "" {
			log.Println("Setting subprocess env: AWS_SESSION_TOKEN, AWS_SECURITY_TOKEN")
			env.Set("AWS_SESSION_TOKEN", val.SessionToken)
			env.Set("AWS_SECURITY_TOKEN", val.SessionToken)
		}
	}

	cmd := exec.Command(input.Command, input.Args...)
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	go func() {
		sig := <-input.Signals
		if cmd.Process != nil {
			cmd.Process.Signal(sig)
		}
	}()

	var waitStatus syscall.WaitStatus
	if err := cmd.Run(); err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			waitStatus = exitError.Sys().(syscall.WaitStatus)
			os.Exit(waitStatus.ExitStatus())
		}
		if err != nil {
			app.Errorf("%v", err)
			return
		}
	}
}

// environ is a slice of strings representing the environment, in the form "key=value".
type environ []string

// Unset an environment variable by key
func (e *environ) Unset(key string) {
	for i := range *e {
		if strings.HasPrefix((*e)[i], key+"=") {
			(*e)[i] = (*e)[len(*e)-1]
			*e = (*e)[:len(*e)-1]
			break
		}
	}
}

// Set adds an environment variable, replacing any existing ones of the same key
func (e *environ) Set(key, val string) {
	e.Unset(key)
	*e = append(*e, key+"="+val)
}
