package main

import (
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/99designs/aws-vault/keyring"
	"github.com/aws/aws-sdk-go/aws/awserr"
)

type ExecCommandInput struct {
	Profile     string
	Command     string
	Args        []string
	Keyring     keyring.Keyring
	Duration    time.Duration
	MfaToken    string
	StartServer bool
}

func ExecCommand(ui Ui, input ExecCommandInput) {
	if os.Getenv("AWS_VAULT") != "" {
		ui.Fatal("aws-vault sessions should be nested with care, unset $AWS_VAULT to force")
	}

	creds, err := NewVaultCredentials(input.Keyring, input.Profile, VaultOptions{
		SessionDuration: input.Duration,
		MfaToken:        input.MfaToken,
	})
	if err != nil {
		ui.Error.Fatal(err)
	}

	val, err := creds.Get()
	if err != nil {
		if awsErr, ok := err.(awserr.Error); ok && awsErr.Code() == "NoCredentialProviders" {
			ui.Error.Fatalf("No credentials found for profile %q", input.Profile)
		} else {
			ui.Error.Fatal(err)
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

	if region, ok := profs[input.Profile]["region"]; ok {
		env.Set("AWS_DEFAULT_REGION", region)
		env.Set("AWS_REGION", region)
	}

	writeEnv := true

	if input.StartServer {
		if err := startCredentialsServer(ui, creds); err != nil {
			ui.Error.Fatal(err)
		} else {
			writeEnv = false
		}
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

	path, err := exec.LookPath(input.Command)
	if err != nil {
		ui.Error.Fatal(err)
	}

	pid, err := syscall.ForkExec(path, append([]string{input.Command}, input.Args...), &syscall.ProcAttr{
		Env:   env,
		Files: []uintptr{0, 1, 2},
	})

	if err != nil {
		ui.Error.Fatal(err)
	}

	proc := &os.Process{Pid: pid}
	proc.Wait()
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
