package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/99designs/aws-vault/keyring"
	"github.com/99designs/aws-vault/prompt"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/skratchdot/open-golang/open"
	"gopkg.in/alecthomas/kingpin.v2"
)

type LoginCommandInput struct {
	Profile                 string
	Keyring                 keyring.Keyring
	MfaToken                string
	MfaPrompt               prompt.PromptFunc
	UseStdout               bool
	FederationTokenDuration time.Duration
	AssumeRoleDuration      time.Duration
}

func LoginCommand(app *kingpin.Application, input LoginCommandInput) {
	if input.FederationTokenDuration > (time.Hour * 12) {
		app.Fatalf("Maximum federation token duration is 12 hours")
		return
	}

	profiles, err := awsConfigFile.Parse()
	if err != nil {
		app.Fatalf("Error parsing config: %v", err)
		return
	}

	if profileConfig, ok := profiles[input.Profile]; ok {
		if _, hasSourceProfile := profileConfig["source_profile"]; !hasSourceProfile {
			app.Fatalf("Login only works for profiles that use AssumeRole")
			return
		}
	}

	provider, err := NewVaultProvider(input.Keyring, input.Profile, VaultOptions{
		AssumeRoleDuration: input.AssumeRoleDuration,
		MfaToken:           input.MfaToken,
		MfaPrompt:          input.MfaPrompt,
		NoSession:          true,
		Profiles:           profiles,
	})
	if err != nil {
		app.Fatalf("Failed to create vault provider: %v", err)
		return
	}

	creds := credentials.NewCredentials(provider)
	val, err := creds.Get()
	if err != nil {
		if awsErr, ok := err.(awserr.Error); ok && awsErr.Code() == "NoCredentialProviders" {
			app.Fatalf("No credentials found for profile %q", input.Profile)
			return
		} else {
			app.Fatalf("Failed to get credentials: %v", err)
		}
	}

	jsonBytes, err := json.Marshal(map[string]string{
		"sessionId":    val.AccessKeyID,
		"sessionKey":   val.SecretAccessKey,
		"sessionToken": val.SessionToken,
	})
	if err != nil {
		app.Fatalf("%v", err)
		return
	}

	req, err := http.NewRequest("GET", "https://signin.aws.amazon.com/federation", nil)
	if err != nil {
		app.Fatalf("%v", err)
		return
	}

	log.Printf("Creating federation login token, expires in %s", input.FederationTokenDuration)

	q := req.URL.Query()
	q.Add("Action", "getSigninToken")
	q.Add("Session", string(jsonBytes))
	q.Add("SessionDuration", fmt.Sprintf("%.f", input.FederationTokenDuration.Seconds()))
	req.URL.RawQuery = q.Encode()

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		app.Fatalf("Failed to create federated token: %v", err)
		return
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		app.Fatalf("%v", err)
		return
	}

	if resp.StatusCode != http.StatusOK {
		log.Printf("Response body was %s", body)
		app.Fatalf("Call to getSigninToken failed with %v", resp.Status)
		return
	}

	var respParsed map[string]string

	if err = json.Unmarshal([]byte(body), &respParsed); err != nil {
		app.Fatalf("Failed to parse response from getSigninToken: %v", err)
		return
	}

	signinToken, ok := respParsed["SigninToken"]
	if !ok {
		app.Fatalf("Expected a response with SigninToken")
		return
	}

	destination := "https://console.aws.amazon.com/"
	if region, ok := profiles[input.Profile]["region"]; ok {
		destination = fmt.Sprintf(
			"https://%s.console.aws.amazon.com/console/home?region=%s",
			region, region,
		)
	}

	loginUrl := fmt.Sprintf(
		"https://signin.aws.amazon.com/federation?Action=login&Issuer=aws-vault&Destination=%s&SigninToken=%s",
		url.QueryEscape(destination),
		url.QueryEscape(signinToken),
	)

	if input.UseStdout {
		fmt.Println(loginUrl)
	} else if err = open.Run(loginUrl); err != nil {
		log.Println(err)
		fmt.Println(loginUrl)
	}
}
