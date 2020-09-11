package cli

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	osexec "os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/99designs/aws-vault/v6/iso8601"
	"github.com/99designs/aws-vault/v6/server"
	"github.com/99designs/aws-vault/v6/vault"
	"github.com/99designs/keyring"
	"github.com/alecthomas/kingpin"
	"github.com/aws/aws-sdk-go/aws/credentials"
)

type ExecCommandInput struct {
	ProfileName      string
	Command          string
	Args             []string
	StartEc2Server   bool
	StartEcsServer   bool
	CredentialHelper bool
	Config           vault.Config
	SessionDuration  time.Duration
	NoSession        bool
}

func (input ExecCommandInput) validate() error {
	if input.StartEc2Server && input.StartEcsServer {
		return fmt.Errorf("Can't use --server with --ecs-server")
	}
	if input.StartEc2Server && input.CredentialHelper {
		return fmt.Errorf("Can't use --server with --json")
	}
	if input.StartEc2Server && input.NoSession {
		return fmt.Errorf("Can't use --server with --no-session")
	}
	if input.StartEcsServer && input.CredentialHelper {
		return fmt.Errorf("Can't use --ecs-server with --json")
	}
	if input.StartEcsServer && input.NoSession {
		return fmt.Errorf("Can't use --ecs-server with --no-session")
	}

	return nil
}

func ConfigureExecCommand(app *kingpin.Application, a *AwsVault) {
	input := ExecCommandInput{}

	cmd := app.Command("exec", "Executes a command with AWS credentials in the environment")

	cmd.Flag("duration", "Duration of the temporary or assume-role session. Defaults to 1h").
		Short('d').
		DurationVar(&input.SessionDuration)

	cmd.Flag("no-session", "Skip creating STS session with GetSessionToken").
		Short('n').
		BoolVar(&input.NoSession)

	cmd.Flag("region", "The AWS region").
		StringVar(&input.Config.Region)

	cmd.Flag("mfa-token", "The MFA token to use").
		Short('t').
		StringVar(&input.Config.MfaToken)

	cmd.Flag("json", "Output credentials in JSON that can be used by credential_process").
		Short('j').
		BoolVar(&input.CredentialHelper)

	cmd.Flag("server", "Alias for --ec2-server. Run a EC2 metadata server in the background for credentials").
		Short('s').
		BoolVar(&input.StartEc2Server)

	cmd.Flag("ec2-server", "Run a EC2 metadata server in the background for credentials").
		BoolVar(&input.StartEc2Server)

	cmd.Flag("ecs-server", "Run a ECS credential server in the background for credentials (the SDK or app must support AWS_CONTAINER_CREDENTIALS_FULL_URI)").
		BoolVar(&input.StartEcsServer)

	cmd.Arg("profile", "Name of the profile").
		Required().
		HintAction(a.MustGetProfileNames).
		StringVar(&input.ProfileName)

	cmd.Arg("cmd", "Command to execute, defaults to $SHELL").
		Default(os.Getenv("SHELL")).
		StringVar(&input.Command)

	cmd.Arg("args", "Command arguments").
		StringsVar(&input.Args)

	cmd.Action(func(c *kingpin.ParseContext) (err error) {
		input.Config.MfaPromptMethod = a.PromptDriver
		input.Config.NonChainedGetSessionTokenDuration = input.SessionDuration
		input.Config.AssumeRoleDuration = input.SessionDuration

		f, err := a.AwsConfigFile()
		if err != nil {
			return err
		}
		keyring, err := a.Keyring()
		if err != nil {
			return err
		}

		err = ExecCommand(input, f, keyring)
		app.FatalIfError(err, "exec")
		return nil
	})
}

func ExecCommand(input ExecCommandInput, f *vault.ConfigFile, keyring keyring.Keyring) error {
	if os.Getenv("AWS_VAULT") != "" {
		return fmt.Errorf("aws-vault sessions should be nested with care, unset $AWS_VAULT to force")
	}

	err := input.validate()
	if err != nil {
		return err
	}

	vault.UseSession = !input.NoSession

	configLoader := vault.ConfigLoader{
		File:          f,
		BaseConfig:    input.Config,
		ActiveProfile: input.ProfileName,
	}
	config, err := configLoader.LoadFromProfile(input.ProfileName)
	if err != nil {
		return err
	}

	ckr := &vault.CredentialKeyring{Keyring: keyring}
	creds, err := vault.NewTempCredentials(config, ckr)
	if err != nil {
		return fmt.Errorf("Error getting temporary credentials: %w", err)
	}

	if input.StartEc2Server {
		return execEc2Server(input, config, creds)
	}

	if input.StartEcsServer {
		return execEcsServer(input, config, creds)
	}

	if input.CredentialHelper {
		return execCredentialHelper(input, config, creds)
	}

	return execEnvironment(input, config, creds)
}

func updateEnvForAwsVault(env environ, profileName string, region string) environ {
	env.Unset("AWS_ACCESS_KEY_ID")
	env.Unset("AWS_SECRET_ACCESS_KEY")
	env.Unset("AWS_SESSION_TOKEN")
	env.Unset("AWS_SECURITY_TOKEN")
	env.Unset("AWS_CREDENTIAL_FILE")
	env.Unset("AWS_DEFAULT_PROFILE")
	env.Unset("AWS_PROFILE")
	env.Unset("AWS_SDK_LOAD_CONFIG")

	env.Set("AWS_VAULT", profileName)

	if region != "" {
		log.Printf("Setting subprocess env: AWS_DEFAULT_REGION=%s, AWS_REGION=%s", region, region)
		env.Set("AWS_DEFAULT_REGION", region)
		env.Set("AWS_REGION", region)
	}

	return env
}

func execEc2Server(input ExecCommandInput, config *vault.Config, creds *credentials.Credentials) error {
	if err := server.StartEc2CredentialsServer(creds, config.Region); err != nil {
		return fmt.Errorf("Failed to start credential server: %w", err)
	}

	env := environ(os.Environ())
	env = updateEnvForAwsVault(env, input.ProfileName, config.Region)

	return execCmd(input.Command, input.Args, env)
}

func execEcsServer(input ExecCommandInput, config *vault.Config, creds *credentials.Credentials) error {
	uri, token, err := server.StartEcsCredentialServer(creds)
	if err != nil {
		return fmt.Errorf("Failed to start credential server: %w", err)
	}

	env := environ(os.Environ())
	env = updateEnvForAwsVault(env, input.ProfileName, config.Region)

	log.Println("Setting subprocess env AWS_CONTAINER_CREDENTIALS_FULL_URI, AWS_CONTAINER_AUTHORIZATION_TOKEN")
	env.Set("AWS_CONTAINER_CREDENTIALS_FULL_URI", uri)
	env.Set("AWS_CONTAINER_AUTHORIZATION_TOKEN", token)

	return execCmd(input.Command, input.Args, env)
}

func execCredentialHelper(input ExecCommandInput, config *vault.Config, creds *credentials.Credentials) error {

	// AwsCredentialHelperData is metadata for AWS CLI credential process
	// See https://docs.aws.amazon.com/cli/latest/topic/config-vars.html#sourcing-credentials-from-external-processes
	type AwsCredentialHelperData struct {
		Version         int    `json:"Version"`
		AccessKeyID     string `json:"AccessKeyId"`
		SecretAccessKey string `json:"SecretAccessKey"`
		SessionToken    string `json:"SessionToken,omitempty"`
		Expiration      string `json:"Expiration,omitempty"`
	}

	val, err := creds.Get()
	if err != nil {
		return fmt.Errorf("Failed to get credentials for %s: %w", input.ProfileName, err)
	}

	credentialData := AwsCredentialHelperData{
		Version:         1,
		AccessKeyID:     val.AccessKeyID,
		SecretAccessKey: val.SecretAccessKey,
		SessionToken:    val.SessionToken,
	}

	if credsExpiresAt, err := creds.ExpiresAt(); err == nil {
		credentialData.Expiration = iso8601.Format(credsExpiresAt)
	}

	json, err := json.Marshal(&credentialData)
	if err != nil {
		return fmt.Errorf("Error creating credential json: %w", err)
	}

	fmt.Print(string(json))

	return nil
}

func execEnvironment(input ExecCommandInput, config *vault.Config, creds *credentials.Credentials) error {
	val, err := creds.Get()
	if err != nil {
		return fmt.Errorf("Failed to get credentials for %s: %w", input.ProfileName, err)
	}

	env := environ(os.Environ())
	env = updateEnvForAwsVault(env, input.ProfileName, config.Region)

	log.Println("Setting subprocess env: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY")
	env.Set("AWS_ACCESS_KEY_ID", val.AccessKeyID)
	env.Set("AWS_SECRET_ACCESS_KEY", val.SecretAccessKey)

	if val.SessionToken != "" {
		log.Println("Setting subprocess env: AWS_SESSION_TOKEN, AWS_SECURITY_TOKEN")
		env.Set("AWS_SESSION_TOKEN", val.SessionToken)
		env.Set("AWS_SECURITY_TOKEN", val.SessionToken)
	}
	if expiration, err := creds.ExpiresAt(); err == nil {
		log.Println("Setting subprocess env: AWS_SESSION_EXPIRATION")
		env.Set("AWS_SESSION_EXPIRATION", iso8601.Format(expiration))
	}

	if !supportsExecSyscall() {
		return execCmd(input.Command, input.Args, env)
	}

	return execSyscall(input.Command, input.Args, env)
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
	log.Printf("Starting child process: %s %s", command, strings.Join(args, " "))

	cmd := osexec.Command(command, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = env

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan)

	if err := cmd.Start(); err != nil {
		return err
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
	log.Printf("Exec command %s %s", command, strings.Join(args, " "))

	argv0, err := osexec.LookPath(command)
	if err != nil {
		return fmt.Errorf("Couldn't find the executable '%s': %w", command, err)
	}

	log.Printf("Found executable %s", argv0)

	argv := make([]string, 0, 1+len(args))
	argv = append(argv, command)
	argv = append(argv, args...)

	return syscall.Exec(argv0, argv, env)
}
