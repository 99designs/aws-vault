package cli

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	osexec "os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/99designs/aws-vault/v7/iso8601"
	"github.com/99designs/aws-vault/v7/server"
	"github.com/99designs/aws-vault/v7/vault"
	"github.com/99designs/keyring"
	"github.com/alecthomas/kingpin"
	"github.com/aws/aws-sdk-go-v2/aws"
)

type ExecCommandInput struct {
	ProfileName      string
	Command          string
	Args             []string
	StartEc2Server   bool
	StartEcsServer   bool
	Lazy             bool
	JSONDeprecated   bool
	Config           vault.Config
	SessionDuration  time.Duration
	NoSession        bool
	UseStdout        bool
	ShowHelpMessages bool
}

func (input ExecCommandInput) validate() error {
	if input.StartEc2Server && input.StartEcsServer {
		return fmt.Errorf("Can't use --ec2-server with --ecs-server")
	}
	if input.StartEc2Server && input.JSONDeprecated {
		return fmt.Errorf("Can't use --ec2-server with --json")
	}
	if input.StartEc2Server && input.NoSession {
		return fmt.Errorf("Can't use --ec2-server with --no-session")
	}
	if input.StartEcsServer && input.JSONDeprecated {
		return fmt.Errorf("Can't use --ecs-server with --json")
	}
	if input.StartEcsServer && input.NoSession {
		return fmt.Errorf("Can't use --ecs-server with --no-session")
	}
	if input.StartEcsServer && input.Config.MfaPromptMethod == "terminal" {
		return fmt.Errorf("Can't use --prompt=terminal with --ecs-server. Specify a different prompt driver")
	}
	if input.StartEc2Server && input.Config.MfaPromptMethod == "terminal" {
		return fmt.Errorf("Can't use --prompt=terminal with --ec2-server. Specify a different prompt driver")
	}

	return nil
}

func hasBackgroundServer(input ExecCommandInput) bool {
	return input.StartEcsServer || input.StartEc2Server
}

func ConfigureExecCommand(app *kingpin.Application, a *AwsVault) {
	input := ExecCommandInput{}

	cmd := app.Command("exec", "Execute a command with AWS credentials.")

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
		Hidden().
		BoolVar(&input.JSONDeprecated)

	cmd.Flag("server", "Alias for --ecs-server").
		Short('s').
		BoolVar(&input.StartEcsServer)

	cmd.Flag("ec2-server", "Run a EC2 metadata server in the background for credentials").
		BoolVar(&input.StartEc2Server)

	cmd.Flag("ecs-server", "Run a ECS credential server in the background for credentials (the SDK or app must support AWS_CONTAINER_CREDENTIALS_FULL_URI)").
		BoolVar(&input.StartEcsServer)

	cmd.Flag("lazy", "When using --ecs-server, lazily fetch credentials").
		BoolVar(&input.Lazy)

	cmd.Flag("stdout", "Print the SSO link to the terminal without automatically opening the browser").
		BoolVar(&input.UseStdout)

	cmd.Arg("profile", "Name of the profile").
		Required().
		HintAction(a.MustGetProfileNames).
		StringVar(&input.ProfileName)

	cmd.Arg("cmd", "Command to execute, defaults to $SHELL").
		StringVar(&input.Command)

	cmd.Arg("args", "Command arguments").
		StringsVar(&input.Args)

	cmd.Action(func(c *kingpin.ParseContext) (err error) {
		input.Config.MfaPromptMethod = a.PromptDriver(hasBackgroundServer(input))
		input.Config.NonChainedGetSessionTokenDuration = input.SessionDuration
		input.Config.AssumeRoleDuration = input.SessionDuration
		input.Config.SSOUseStdout = input.UseStdout
		input.ShowHelpMessages = input.Command == "" && isATerminal() && os.Getenv("AWS_VAULT_DISABLE_HELP_MESSAGE") != "1"

		f, err := a.AwsConfigFile()
		if err != nil {
			return err
		}
		keyring, err := a.Keyring()
		if err != nil {
			return err
		}

		if input.JSONDeprecated {
			exportCommandInput := ExportCommandInput{
				ProfileName:     input.ProfileName,
				Format:          "json",
				Config:          input.Config,
				SessionDuration: input.SessionDuration,
				NoSession:       input.NoSession,
			}

			err = ExportCommand(exportCommandInput, f, keyring)
		} else {
			err = ExecCommand(input, f, keyring)
		}

		app.FatalIfError(err, "exec")
		return nil
	})
}

func ExecCommand(input ExecCommandInput, f *vault.ConfigFile, keyring keyring.Keyring) error {
	if os.Getenv("AWS_VAULT") != "" {
		return fmt.Errorf("running in an existing aws-vault subshell; 'exit' from the subshell or unset AWS_VAULT to force")
	}

	if err := input.validate(); err != nil {
		return err
	}

	vault.UseSession = !input.NoSession

	config, err := vault.NewConfigLoader(input.Config, f, input.ProfileName).LoadFromProfile(input.ProfileName)
	if err != nil {
		return fmt.Errorf("Error loading config: %w", err)
	}

	credsProvider, err := vault.NewTempCredentialsProvider(config, &vault.CredentialKeyring{Keyring: keyring})
	if err != nil {
		return fmt.Errorf("Error getting temporary credentials: %w", err)
	}

	subshellHelp := ""
	if input.Command == "" {
		input.Command = getDefaultShell()
		subshellHelp = fmt.Sprintf("Starting subshell %s, use `exit` to exit the subshell", input.Command)
	}

	cmdEnv := createEnv(input.ProfileName, config.Region)

	if input.StartEc2Server {
		printHelpMessage("Starting an EC2 credential server on 169.254.169.254:80", input.ShowHelpMessages)
		if err = server.StartEc2CredentialsServer(context.TODO(), credsProvider, config.Region); err != nil {
			return fmt.Errorf("Failed to start credential server: %w", err)
		}
		printHelpMessage(subshellHelp, input.ShowHelpMessages)
	} else if input.StartEcsServer {
		printHelpMessage("Starting an ECS credential server; your app's AWS sdk must support AWS_CONTAINER_CREDENTIALS_FULL_URI.", input.ShowHelpMessages)
		if err = startEcsServerAndSetEnv(credsProvider, config, input.Lazy, &cmdEnv); err != nil {
			return err
		}
		printHelpMessage(subshellHelp, input.ShowHelpMessages)
	} else {
		if err = addCredsToEnv(credsProvider, input.ProfileName, &cmdEnv); err != nil {
			return err
		}
		printHelpMessage(subshellHelp, input.ShowHelpMessages)

		if osSupportsExecSyscall() {
			return doExecSyscall(input.Command, input.Args, cmdEnv)
		}
	}

	return runChildProcess(input.Command, input.Args, cmdEnv)
}

func printHelpMessage(helpMsg string, showHelpMessages bool) {
	if helpMsg != "" {
		if showHelpMessages {
			printToStderr(helpMsg)
		} else {
			log.Println(helpMsg)
		}
	}
}

func printToStderr(helpMsg string) {
	fmt.Fprint(os.Stderr, helpMsg, "\n")
}

func createEnv(profileName string, region string) environ {
	env := environ(os.Environ())
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
		// AWS_REGION is used by most SDKs. But boto3 (Python SDK) uses AWS_DEFAULT_REGION
		// See https://docs.aws.amazon.com/sdkref/latest/guide/feature-region.html
		log.Printf("Setting subprocess env: AWS_REGION=%s, AWS_DEFAULT_REGION=%s", region, region)
		env.Set("AWS_REGION", region)
		env.Set("AWS_DEFAULT_REGION", region)
	}

	return env
}

func startEcsServerAndSetEnv(credsProvider aws.CredentialsProvider, config *vault.Config, lazy bool, cmdEnv *environ) error {
	ecsServer, err := server.NewEcsServer(context.TODO(), credsProvider, config, "", 0, lazy)
	if err != nil {
		return err
	}
	go func() {
		err = ecsServer.Serve()
		if err != http.ErrServerClosed { // ErrServerClosed is a graceful close
			log.Fatalf("ecs server: %s", err.Error())
		}
	}()

	log.Println("Setting subprocess env AWS_CONTAINER_CREDENTIALS_FULL_URI, AWS_CONTAINER_AUTHORIZATION_TOKEN")
	cmdEnv.Set("AWS_CONTAINER_CREDENTIALS_FULL_URI", ecsServer.BaseURL())
	cmdEnv.Set("AWS_CONTAINER_AUTHORIZATION_TOKEN", ecsServer.AuthToken())

	return nil
}

func addCredsToEnv(credsProvider aws.CredentialsProvider, profileName string, cmdEnv *environ) error {
	creds, err := credsProvider.Retrieve(context.TODO())
	if err != nil {
		return fmt.Errorf("Failed to get credentials for %s: %w", profileName, err)
	}

	log.Println("Setting subprocess env: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY")
	cmdEnv.Set("AWS_ACCESS_KEY_ID", creds.AccessKeyID)
	cmdEnv.Set("AWS_SECRET_ACCESS_KEY", creds.SecretAccessKey)

	if creds.SessionToken != "" {
		log.Println("Setting subprocess env: AWS_SESSION_TOKEN")
		cmdEnv.Set("AWS_SESSION_TOKEN", creds.SessionToken)
	}
	if creds.CanExpire {
		log.Println("Setting subprocess env: AWS_CREDENTIAL_EXPIRATION")
		cmdEnv.Set("AWS_CREDENTIAL_EXPIRATION", iso8601.Format(creds.Expires))
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

func getDefaultShell() string {
	command := os.Getenv("SHELL")
	if command == "" {
		if runtime.GOOS == "windows" {
			command = "cmd.exe"
		} else {
			command = "/bin/sh"
		}
	}
	return command
}

func runChildProcess(command string, args []string, env []string) error {
	log.Printf("Starting subprocess: %s %s", command, strings.Join(args, " "))

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

	// proxy signals to process
	go func() {
		for {
			sig := <-sigChan
			_ = cmd.Process.Signal(sig)
		}
	}()

	if err := cmd.Wait(); err != nil {
		_ = cmd.Process.Signal(os.Kill)
		return fmt.Errorf("Failed to wait for command termination: %v", err)
	}

	waitStatus := cmd.ProcessState.Sys().(syscall.WaitStatus)
	os.Exit(waitStatus.ExitStatus())
	return nil
}

func osSupportsExecSyscall() bool {
	return runtime.GOOS == "linux" || runtime.GOOS == "darwin" || runtime.GOOS == "freebsd" || runtime.GOOS == "openbsd"
}

func doExecSyscall(command string, args []string, env []string) error {
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
