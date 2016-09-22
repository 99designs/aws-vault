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

func LoginCommand(ui Ui, input LoginCommandInput) {
	if input.FederationTokenDuration > (time.Hour * 12) {
		ui.Error.Fatalf("Maximum federation token duration is 12 hours")
		return
	}

	provider, err := NewVaultProvider(input.Keyring, input.Profile, VaultOptions{
		AssumeRoleDuration: input.AssumeRoleDuration,
		MfaToken:           input.MfaToken,
		MfaPrompt:          input.MfaPrompt,
		NoSession:          true,
	})
	if err != nil {
		ui.Error.Fatal(err)
	}

	creds := credentials.NewCredentials(provider)
	val, err := creds.Get()
	if err != nil {
		if awsErr, ok := err.(awserr.Error); ok && awsErr.Code() == "NoCredentialProviders" {
			ui.Error.Fatalf("No credentials found for profile %q", input.Profile)
		} else {
			ui.Error.Fatal(err)
		}
	}

	jsonBytes, err := json.Marshal(map[string]string{
		"sessionId":    val.AccessKeyID,
		"sessionKey":   val.SecretAccessKey,
		"sessionToken": val.SessionToken,
	})
	if err != nil {
		ui.Error.Fatal(err)
	}

	req, err := http.NewRequest("GET", "https://signin.aws.amazon.com/federation", nil)
	if err != nil {
		ui.Error.Fatal(err)
	}

	log.Printf("Creating federation login token, expires in %s", input.FederationTokenDuration)

	q := req.URL.Query()
	q.Add("Action", "getSigninToken")
	q.Add("Session", string(jsonBytes))
	q.Add("SessionDuration", fmt.Sprintf("%.f", input.FederationTokenDuration.Seconds()))
	req.URL.RawQuery = q.Encode()

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		ui.Error.Fatal(err)
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		ui.Error.Fatal(err)
	}

	var respParsed map[string]string

	if err = json.Unmarshal([]byte(body), &respParsed); err != nil {
		ui.Error.Fatal(err)
	}

	signinToken, ok := respParsed["SigninToken"]
	if !ok {
		ui.Error.Fatal("Expected a response with SigninToken")
	}

	loginUrl := fmt.Sprintf(
		"https://signin.aws.amazon.com/federation?Action=login&Issuer=aws-vault&Destination=%s&SigninToken=%s",
		url.QueryEscape("https://console.aws.amazon.com/"),
		url.QueryEscape(signinToken),
	)

	if input.UseStdout {
		fmt.Println(loginUrl)
	} else if err = open.Run(loginUrl); err != nil {
		log.Println(err)
		fmt.Println(loginUrl)
	}
}
