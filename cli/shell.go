package cli

import (
	"errors"
	"fmt"
	"github.com/99designs/aws-vault/vault"
	"github.com/99designs/keyring"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"gopkg.in/alecthomas/kingpin.v2"
	"os"
	osexec "os/exec"
	"runtime"
	"syscall"
)

type ShellCommandInput struct {
	ProfileName string
	Command     string
	Args        []string
	Keyring     keyring.Keyring
	StartServer bool
	Config      vault.Config
}

func ConfigureShellCommand(app *kingpin.Application) {
	input := ShellCommandInput{}

	cmd := app.Command("shell", "Provides a shell with credentials set in the environment")
	cmd.Flag("no-session", "Use master credentials, no session created").
		Short('n').
		BoolVar(&input.Config.NoSession)

	cmd.Flag("session-ttl", "Expiration time for aws session").
		Default("4h").
		Envar("AWS_SESSION_TTL").
		Short('t').
		DurationVar(&input.Config.SessionDuration)

	cmd.Flag("assume-role-ttl", "Expiration time for aws assumed role").
		Default("15m").
		Envar("AWS_ASSUME_ROLE_TTL").
		DurationVar(&input.Config.AssumeRoleDuration)

	cmd.Flag("mfa-token", "The mfa token to use").
		Short('m').
		StringVar(&input.Config.MfaToken)

	cmd.Flag("server", "Run the server in the background for credentials").
		Short('s').
		BoolVar(&input.StartServer)

	cmd.Arg("profile", "Name of the profile").
		Required().
		HintAction(awsConfigFile.ProfileNames).
		StringVar(&input.ProfileName)

	cmd.Action(func(c *kingpin.ParseContext) error {
		input.Keyring = keyringImpl
		input.Config.MfaPromptMethod = GlobalFlags.PromptDriver
		ShellCommand(app, input)
		return nil
	})
}

func ShellCommand(app *kingpin.Application, input ShellCommandInput) {
	if os.Getenv("AWS_VAULT") != "" {
		app.Fatalf("aws-vault sessions should be nested with care, unset $AWS_VAULT to force")
		return
	}

	if input.Config.NoSession && input.StartServer {
		app.Fatalf("Can't start a credential server without a session")
		return
	}

	err := configLoader.LoadFromProfile(input.ProfileName, &input.Config)
	if err != nil {
		app.Fatalf("%v", err)
		return
	}

	var creds *credentials.Credentials

	creds, err = vault.NewTempCredentials(input.Keyring, &input.Config)
	if err != nil {
		app.Fatalf("%v", err)
		return
	}

	var val credentials.Value

	val, err = creds.Get()
	if err != nil {
		app.Fatalf(FormatCredentialError(err, input.Config.CredentialsName))
		return
	}

	envvars := map[string]string{
		"AWS_ACCESS_KEY_ID":     val.AccessKeyID,
		"AWS_ACCESS_KEY":        val.AccessKeyID,
		"AWS_SECRET_ACCESS_KEY": val.SecretAccessKey,
		"AWS_SECRET_KEY":        val.SecretAccessKey,
		"AWS_SESSION_TOKEN":     val.SessionToken,
		"AWS_REGION":            input.Config.Region,
		"AWS_DEFAULT_REGION":    input.Config.Region,
	}

	if err = forkShell(envvars); err != nil {
		app.Fatalf("%v", err)
	}
}

func forkShell(envvars map[string]string) error {
	supportedOSes := []string{"darwin", "freebsd", "linux", "netbsd", "openbsd", "windows"}
	unixLikeOSes := []string{"darwin", "freebsd", "linux", "netbsd", "openbsd"}
	thisOS := runtime.GOOS

	if !StringInSlice(thisOS, supportedOSes) {
		return errors.New("unable to fork shell as OS is not supported")
	} else {
		fmt.Println("launching shell with temporary credentials...")
	}

	if StringInSlice(thisOS, unixLikeOSes) {
		for k, v := range envvars {
			_ = os.Setenv(k, v)
		}
		err := syscall.Exec(os.Getenv("SHELL"), []string{os.Getenv("SHELL")}, syscall.Environ())
		if err != nil {
			return err
		}
	} else if thisOS == "windows" {
		cmd := osexec.Command("PowerShell")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Stdin = os.Stdin
		newEnv := os.Environ()
		for k, v := range envvars {
			newEnv = append(newEnv, fmt.Sprintf("%s=%s", k, v))
		}
		cmd.Env = newEnv
		return cmd.Run()
	}
	return nil
}

func StringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}
