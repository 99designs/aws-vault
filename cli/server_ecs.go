package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/99designs/aws-vault/prompt"
	"github.com/99designs/aws-vault/server"
	"github.com/99designs/aws-vault/vault"
	"github.com/99designs/keyring"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"gopkg.in/alecthomas/kingpin.v2"
)

const (
	kEcsPrivilegedIP = "169.254.170.2"
	kEcsCredsPrefix  = "/creds/"
)

type EcsServerCommandInput struct {
	Privileged   bool
	ServerPort   int
	AuthToken    string
	Duration     time.Duration
	RoleDuration time.Duration
	Keyring      keyring.Keyring
	MfaPrompt    prompt.PromptFunc
}

func ConfigureEcsServerCommand(app *kingpin.Application) {
	input := EcsServerCommandInput{}

	cmd := app.Command("ecs-server", "Run a local ECS credentials server")

	cmd.Flag("privileged", "Start the server on the privileged IP+port used by ECS (requires superuser)").
		BoolVar(&input.Privileged)

	cmd.Flag("port", "Port to listen on for the credentials server (ignored in privileged mode)").
		Default("9999").
		Short('p').
		IntVar(&input.ServerPort)

	cmd.Flag("session-ttl", "Expiration time for aws session").
		Default("4h").
		Envar("AWS_SESSION_TTL").
		Short('t').
		DurationVar(&input.Duration)

	cmd.Flag("assume-role-ttl", "Expiration time for aws assumed role").
		Default("15m").
		Envar("AWS_ASSUME_ROLE_TTL").
		DurationVar(&input.RoleDuration)

	cmd.Flag("auth-token", "Require an Authentication token when requesting credentials").
		Default("").
		Envar("AWS_VAULT_AUTH_TOKEN").
		StringVar(&input.AuthToken)

	cmd.Action(func(c *kingpin.ParseContext) error {
		input.Keyring = keyringImpl
		input.MfaPrompt = prompt.Method(GlobalFlags.PromptDriver)
		EcsServerCommand(app, input)
		return nil
	})
}

func EcsServerCommand(app *kingpin.Application, input EcsServerCommandInput) {
	sess, err := session.NewSession()
	app.FatalIfError(err, "Creating AWS session")

	addr := "localhost"
	if input.Privileged {
		fmt.Printf("Running in privileged mode\n")
		if res, err := server.InstallNetworkAlias(kEcsPrivilegedIP); err != nil {
			fmt.Print(string(res))
			app.Fatalf("Error installing network alias: %s", err.Error())
		}

		addr = kEcsPrivilegedIP
		input.ServerPort = 80
	}

	l, err := net.Listen("tcp", fmt.Sprintf("%s:%d", addr, input.ServerPort))
	app.FatalIfError(err, "Binding port %d", input.ServerPort)

	fmt.Printf("Local ECS credentials server running on %s\n", l.Addr())

	if input.Privileged {
		fmt.Printf("Use AWS_CONTAINER_CREDENTIALS_RELATIVE_URI=%s{profile_id}[/{role_arn}]\n", kEcsCredsPrefix)
	} else {
		fmt.Printf("Use AWS_CONTAINER_CREDENTIALS_FULL_URI=http://%s%s{profile_id}[/{role_arn}]\n", l.Addr(), kEcsCredsPrefix)
	}

	if input.AuthToken != "" {
		fmt.Printf("Authorization token required! Remember to also set AWS_CONTAINER_AUTHORIZATION_TOKEN to its value\n")
	}

	app.FatalIfError(http.Serve(l, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			ecsServerError(w, err, http.StatusInternalServerError)
			return
		}

		if !net.ParseIP(ip).IsLoopback() && ip != kEcsPrivilegedIP {
			ecsServerError(w, fmt.Errorf("Access denied from non-localhost address %s", ip), http.StatusUnauthorized)
			return
		}

		if r.Header.Get("Authorization") != input.AuthToken {
			ecsServerError(w, errors.New("Invalid Authorization token"), http.StatusUnauthorized)
			return
		}

		if r.Method != http.MethodGet {
			ecsServerError(w, errors.New("Only GET requests are supported"), http.StatusMethodNotAllowed)
			return
		}

		// Simple way to protect the credentials from being queried from a browser
		if r.Header.Get("Origin") != "" {
			ecsServerError(w, errors.New("CORS access from a browser is not allowed"), http.StatusUnauthorized)
			return
		}

		log.Printf("Received credentials request from RemoteAddr = %v", r.RemoteAddr)

		if !strings.HasPrefix(r.URL.Path, kEcsCredsPrefix) {
			ecsServerError(w, errors.New("404 page not found"), http.StatusNotFound)
			return
		}

		pathSpl := strings.SplitN(strings.TrimPrefix(r.URL.Path, kEcsCredsPrefix), "/", 2)
		if pathSpl == nil {
			ecsServerError(w, errors.New("404 page not found"), http.StatusNotFound)
			return
		}

		vaultProvider, err := vault.NewVaultProvider(input.Keyring, pathSpl[0], vault.VaultOptions{
			SessionDuration:    input.Duration,
			AssumeRoleDuration: input.RoleDuration,
			MfaPrompt:          input.MfaPrompt,
			Config:             awsConfig,
		})
		if err != nil {
			ecsServerError(w, err, http.StatusUnauthorized)
			return
		}

		assumedCreds := credentials.NewCredentials(vaultProvider)

		if len(pathSpl) == 2 {
			// We've got another role to chain with
			roleArn, err := arn.Parse(pathSpl[1])
			if err != nil {
				ecsServerError(w, err, http.StatusBadRequest)
				return
			}

			log.Printf("Assuming role %s using '%s' profile credentials", roleArn, pathSpl[0])
			assumedCreds = stscreds.NewCredentials(sess.Copy(&aws.Config{Credentials: assumedCreds}), roleArn.String())
		}

		creds, err := assumedCreds.Get()
		if err != nil {
			ecsServerError(w, err, http.StatusUnauthorized)
			return
		}

		expiration, err := assumedCreds.ExpiresAt()
		if err != nil {
			ecsServerError(w, err, http.StatusUnauthorized)
			return
		}

		log.Printf("Serving credentials via http ****************%s, expiration of %s (%s)",
			creds.AccessKeyID[len(creds.AccessKeyID)-4:],
			expiration.Format("2006-01-02T15:04:05Z"),
			expiration.Sub(time.Now()))

		w.Header().Set("Content-Type", "application/json")
		err = json.NewEncoder(w).Encode(map[string]interface{}{
			"AccessKeyId":     creds.AccessKeyID,
			"SecretAccessKey": creds.SecretAccessKey,
			"Token":           creds.SessionToken,
			"Expiration":      expiration.Format("2006-01-02T15:04:05Z"),
		})
		if err != nil {
			ecsServerError(w, err, http.StatusInternalServerError)
			return
		}
	})), "Error starting credential server")
}

func ecsServerError(w http.ResponseWriter, err error, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	response := map[string]string{}
	if awsErr, ok := err.(awserr.Error); ok {
		response["code"] = awsErr.Code()
		response["message"] = awsErr.Message()
		if origErr := awsErr.OrigErr(); origErr != nil {
			response["cause"] = origErr.Error()
		}
	} else {
		response["code"] = strings.ReplaceAll(http.StatusText(status), " ", "")
		response["message"] = err.Error()
	}

	log.Printf("Error: %s", err.Error())
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Error writing HTTP error response: %s", err.Error())
	}
}
