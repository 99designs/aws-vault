package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"github.com/99designs/aws-vault/keyring"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
)

type LoginCommandInput struct {
	Profile string
	Keyring keyring.Keyring
}

func LoginCommand(ui Ui, input LoginCommandInput) {
	provider, err := NewVaultProvider(input.Keyring, input.Profile, time.Hour)
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

	q := req.URL.Query()
	q.Add("Action", "getSigninToken")
	q.Add("Session", string(jsonBytes))
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

	fmt.Printf(
		"https://signin.aws.amazon.com/federation?Action=login&Issuer=aws-vault&Destination=%s&SigninToken=%s",
		url.QueryEscape("https://console.aws.amazon.com/"),
		url.QueryEscape(signinToken),
	)
}
