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
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/sts"
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
		}
		app.Fatalf("Failed to get credentials: %v", err)
	}

	var isFederated bool
	var sessionDuration = input.FederationTokenDuration

	// if AssumeRole isn't used, GetFederationToken has to be used for IAM credentials
	if val.SessionToken == "" {
		log.Printf("No session token found, calling GetFederationToken")
		stsCreds, err := getFederationToken(val, input.FederationTokenDuration)
		if err != nil {
			app.Fatalf("Failed to call GetFederationToken: %v", err)
			return
		}

		val.AccessKeyID = *stsCreds.AccessKeyId
		val.SecretAccessKey = *stsCreds.SecretAccessKey
		val.SessionToken = *stsCreds.SessionToken
		isFederated = true
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

	log.Printf("Creating login token, expires in %s", sessionDuration)

	q := req.URL.Query()
	q.Add("Action", "getSigninToken")
	q.Add("Session", string(jsonBytes))

	// not needed for federation tokens
	if !isFederated {
		q.Add("SessionDuration", fmt.Sprintf("%.f", sessionDuration.Seconds()))
	}

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

func getFederationToken(creds credentials.Value, d time.Duration) (*sts.Credentials, error) {
	client := sts.New(session.New(&aws.Config{
		Credentials: credentials.NewCredentials(&credentials.StaticProvider{Value: creds}),
	}))

	params := &sts.GetFederationTokenInput{
		Name:            aws.String("federated-user"),
		DurationSeconds: aws.Int64(int64(d.Seconds())),
	}

	if username, _ := getUserName(creds); username != "" {
		params.Name = aws.String(username)
	}

	resp, err := client.GetFederationToken(params)
	if err != nil {
		return nil, err
	}

	return resp.Credentials, nil
}

func getUserName(creds credentials.Value) (string, error) {
	client := iam.New(session.New(&aws.Config{
		Credentials: credentials.NewCredentials(&credentials.StaticProvider{Value: creds}),
	}))

	resp, err := client.GetUser(&iam.GetUserInput{})
	if err != nil {
		return "", err
	}

	return *resp.User.UserName, nil
}
