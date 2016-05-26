package main

import (
	"log"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/99designs/aws-vault/keyring"
	"github.com/99designs/aws-vault/prompt"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
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

func ExecCommand(ui Ui, input ExecCommandInput) {
	if os.Getenv("AWS_VAULT") != "" {
		ui.Fatal("aws-vault sessions should be nested with care, unset $AWS_VAULT to force")
	}

	var (
		err      error
		val      credentials.Value
		writeEnv bool = true
	)

	if input.NoSession {
		if input.StartServer {
			ui.Error.Fatal("Can't start a credential server without a session")
		}

		log.Println("No session requested, be careful!")
		provider := &KeyringProvider{input.Keyring, input.Profile}
		val, err = provider.Retrieve()
		if err != nil {
			log.Fatal(err)
		}
	} else {
		creds, err := NewVaultCredentials(input.Keyring, input.Profile, VaultOptions{
			SessionDuration:    input.Duration,
			AssumeRoleDuration: input.RoleDuration,
			MfaToken:           input.MfaToken,
			MfaPrompt:          input.MfaPrompt,
		})
		if err != nil {
			ui.Error.Fatal(err)
		}

		val, err = creds.Get()
		if err != nil {
			if awsErr, ok := err.(awserr.Error); ok && awsErr.Code() == "NoCredentialProviders" {
				ui.Error.Fatalf("No credentials found for profile %q", input.Profile)
			} else {
				ui.Error.Fatal(err)
			}
		}

		if input.StartServer {
			if err := startCredentialsServer(ui, creds); err != nil {
				ui.Error.Fatal(err)
			} else {
				writeEnv = false
			}
		}

	}

	profs, err := parseProfiles()
	if err != nil {
		ui.Error.Fatal(err)
	}

	env := environ(os.Environ())
	env.Set("AWS_CONFIG_FILE", "/dev/null")
	env.Set("AWS_VAULT", input.Profile)

	env.Unset("AWS_ACCESS_KEY_ID")
	env.Unset("AWS_SECRET_ACCESS_KEY")
	env.Unset("AWS_CREDENTIAL_FILE")
	env.Unset("AWS_DEFAULT_PROFILE")
	env.Unset("AWS_PROFILE")

	if region, ok := profs[input.Profile]["region"]; ok {
		env.Set("AWS_DEFAULT_REGION", region)
		env.Set("AWS_REGION", region)
	}

	if writeEnv {
		ui.Debug.Println("Writing temporary credentials to ENV")

		env.Set("AWS_ACCESS_KEY_ID", val.AccessKeyID)
		env.Set("AWS_SECRET_ACCESS_KEY", val.SecretAccessKey)

		if val.SessionToken != "" {
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
		if err != nil {
			ui.Error.Println(err)
		}
		if exitError, ok := err.(*exec.ExitError); ok {
			waitStatus = exitError.Sys().(syscall.WaitStatus)
			os.Exit(waitStatus.ExitStatus())
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
