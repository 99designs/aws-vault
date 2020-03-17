package cli

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/99designs/aws-vault/server"
	"github.com/99designs/aws-vault/vault"
	"github.com/99designs/keyring"
	"gopkg.in/alecthomas/kingpin.v2"
)

type ExecCommandInput struct {
	ProfileName      string
	Command          string
	Args             []string
	Keyring          keyring.Keyring
	StartServer      bool
	CredentialHelper bool
	Config           vault.Config
	SessionDuration  time.Duration
	NoSession        bool
}

// AwsCredentialHelperData is metadata for AWS CLI credential process
// See https://docs.aws.amazon.com/cli/latest/topic/config-vars.html#sourcing-credentials-from-external-processes
type AwsCredentialHelperData struct {
	Version         int    `json:"Version"`
	AccessKeyID     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	SessionToken    string `json:"SessionToken"`
	Expiration      string `json:"Expiration,omitempty"`
}

func ConfigureExecCommand(app *kingpin.Application) {
	input := ExecCommandInput{}

	cmd := app.Command("exec", "Executes a command with AWS credentials in the environment")

	cmd.Flag("duration", "Duration of the temporary or assume-role session. Defaults to 1h").
		Short('d').
		DurationVar(&input.SessionDuration)

	cmd.Flag("no-session", "Skip creating STS session with GetSessionToken").
		Short('n').
		BoolVar(&input.NoSession)

	cmd.Flag("mfa-token", "The MFA token to use").
		Short('t').
		StringVar(&input.Config.MfaToken)

	cmd.Flag("json", "AWS credential helper. Ref: https://docs.aws.amazon.com/cli/latest/topic/config-vars.html#sourcing-credentials-from-external-processes").
		Short('j').
		BoolVar(&input.CredentialHelper)

	cmd.Flag("server", "Run the server in the background for credentials").
		Short('s').
		BoolVar(&input.StartServer)

	cmd.Arg("profile", "Name of the profile").
		Required().
		HintAction(getProfileNames).
		StringVar(&input.ProfileName)

	cmd.Arg("cmd", "Command to execute, defaults to $SHELL").
		Default(os.Getenv("SHELL")).
		StringVar(&input.Command)

	cmd.Arg("args", "Command arguments").
		StringsVar(&input.Args)

	cmd.Action(func(c *kingpin.ParseContext) error {
		input.Keyring = keyringImpl
		input.Config.MfaPromptMethod = GlobalFlags.PromptDriver
		input.Config.NonChainedGetSessionTokenDuration = input.SessionDuration
		input.Config.AssumeRoleDuration = input.SessionDuration
		app.FatalIfError(ExecCommand(input), "exec")
		return nil
	})
}

func ExecCommand(input ExecCommandInput) error {
	if os.Getenv("AWS_VAULT") != "" {
		return fmt.Errorf("aws-vault sessions should be nested with care, unset $AWS_VAULT to force")
	}

	vault.UseSession = !input.NoSession
	setEnv := true

	configLoader.BaseConfig = input.Config
	configLoader.ActiveProfile = input.ProfileName
	config, err := configLoader.LoadFromProfile(input.ProfileName)
	if err != nil {
		return err
	}

	credKeyring := &vault.CredentialKeyring{Keyring: input.Keyring}
	creds, err := vault.NewTempCredentials(config, credKeyring)
	if err != nil {
		return fmt.Errorf("Error getting temporary credentials: %w", err)
	}

	val, err := creds.Get()
	if err != nil {
		return fmt.Errorf("Failed to get credentials for %s: %w", input.ProfileName, err)
	}

	if input.StartServer {
		if err := server.StartCredentialsServer(creds); err != nil {
			return fmt.Errorf("Failed to start credential server: %w", err)
		}
		if err := server.StartIdentityDocumentServer(config); err != nil {
			return fmt.Errorf("Failed to start identity document server: %w", err)
		}
		setEnv = false
	}

	if input.CredentialHelper {
		credentialData := AwsCredentialHelperData{
			Version:         1,
			AccessKeyID:     val.AccessKeyID,
			SecretAccessKey: val.SecretAccessKey,
			SessionToken:    val.SessionToken,
		}
		if !input.NoSession {
			credsExprest, err := creds.ExpiresAt()
			if err != nil {
				return fmt.Errorf("Error getting credential expiration: %w", err)
			}
			credentialData.Expiration = credsExprest.Format("2006-01-02T15:04:05Z")
		}
		json, err := json.Marshal(&credentialData)
		if err != nil {
			return fmt.Errorf("Error creating credential json: %w", err)
		}
		fmt.Print(string(json))
	} else {

		env := environ(os.Environ())
		env.Set("AWS_VAULT", input.ProfileName)

		env.Unset("AWS_ACCESS_KEY_ID")
		env.Unset("AWS_SECRET_ACCESS_KEY")
		env.Unset("AWS_CREDENTIAL_FILE")
		env.Unset("AWS_DEFAULT_PROFILE")
		env.Unset("AWS_PROFILE")

		if config.Region != "" {
			log.Printf("Setting subprocess env: AWS_DEFAULT_REGION=%s, AWS_REGION=%s", config.Region, config.Region)
			env.Set("AWS_DEFAULT_REGION", config.Region)
			env.Set("AWS_REGION", config.Region)
		}

		if setEnv {
			log.Println("Setting subprocess env: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY")
			env.Set("AWS_ACCESS_KEY_ID", val.AccessKeyID)
			env.Set("AWS_SECRET_ACCESS_KEY", val.SecretAccessKey)

			if val.SessionToken != "" {
				log.Println("Setting subprocess env: AWS_SESSION_TOKEN, AWS_SECURITY_TOKEN")
				env.Set("AWS_SESSION_TOKEN", val.SessionToken)
				env.Set("AWS_SECURITY_TOKEN", val.SessionToken)
				expiration, err := creds.ExpiresAt()
				if err == nil {
					log.Println("Setting subprocess env: AWS_SESSION_EXPIRATION")
					env.Set("AWS_SESSION_EXPIRATION", expiration.Format(time.RFC3339))
				}
			}
		}

		if input.StartServer {
			err = execCmd(input.Command, input.Args, env)
		} else {
			err = execSyscall(input.Command, input.Args, env)
		}

		if err != nil {
			return fmt.Errorf("Error execing process: %w", err)
		}
	}

	return nil
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

func execCmd(command string, args []string, env []string) error {
	cmd := exec.Command(command, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = env

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan)

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("Failed to start command: %v", err)
	}

	go func() {
		for {
			sig := <-sigChan
			cmd.Process.Signal(sig)
		}
	}()

	if err := cmd.Wait(); err != nil {
		cmd.Process.Signal(os.Kill)
		return fmt.Errorf("Failed to wait for command termination: %v", err)
	}

	waitStatus := cmd.ProcessState.Sys().(syscall.WaitStatus)
	os.Exit(waitStatus.ExitStatus())
	return nil
}

func supportsExecSyscall() bool {
	return runtime.GOOS == "linux" || runtime.GOOS == "darwin" || runtime.GOOS == "freebsd"
}

func execSyscall(command string, args []string, env []string) error {
	if !supportsExecSyscall() {
		return execCmd(command, args, env)
	}

	argv0, err := exec.LookPath(command)
	if err != nil {
		return err
	}

	argv := make([]string, 0, 1+len(args))
	argv = append(argv, command)
	argv = append(argv, args...)

	return syscall.Exec(argv0, argv, env)
}
