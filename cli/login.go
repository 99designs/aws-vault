package cli

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/99designs/aws-vault/prompt"
	"github.com/99designs/aws-vault/vault"
	"github.com/99designs/keyring"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/skratchdot/open-golang/open"
	"gopkg.in/alecthomas/kingpin.v2"
)

const allowAllIAMPolicy = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`

type LoginCommandInput struct {
	ProfileName             string
	Keyring                 keyring.Keyring
	UseStdout               bool
	FederationTokenDuration time.Duration
	Path                    string
	Config                  vault.Config
}

func ConfigureLoginCommand(app *kingpin.Application) {
	input := LoginCommandInput{}

	cmd := app.Command("login", "Generate a login link for the AWS Console")
	cmd.Flag("no-session", "Use root credentials, no session created").
		Short('n').
		BoolVar(&input.Config.NoSession)

	cmd.Arg("profile", "Name of the profile").
		Required().
		HintAction(awsConfigFile.ProfileNames).
		StringVar(&input.ProfileName)

	cmd.Flag("mfa-token", "The mfa token to use").
		Short('t').
		StringVar(&input.Config.MfaToken)

	cmd.Flag("mfa-serial", "The identification number of the MFA device to use").
		StringVar(&input.Config.MfaSerial)

	cmd.Flag("path", "The AWS service you would like access").
		StringVar(&input.Path)

	cmd.Flag("federation-token-ttl", "Expiration time for aws console session").
		Default("12h").
		Envar("AWS_FEDERATION_TOKEN_TTL").
		Short('f').
		DurationVar(&input.FederationTokenDuration)

	cmd.Flag("assume-role-ttl", "Expiration time for aws assumed role").
		Default("15m").
		Envar("AWS_ASSUME_ROLE_TTL").
		DurationVar(&input.Config.AssumeRoleDuration)

	cmd.Flag("stdout", "Print login URL to stdout instead of opening in default browser").
		Short('s').
		BoolVar(&input.UseStdout)

	cmd.Action(func(c *kingpin.ParseContext) error {
		input.Config.MfaPrompt = prompt.Method(GlobalFlags.PromptDriver)
		input.Keyring = keyringImpl
		LoginCommand(app, input)
		return nil
	})
}

func LoginCommand(app *kingpin.Application, input LoginCommandInput) {
	if input.FederationTokenDuration > (time.Hour * 12) {
		app.Fatalf("Maximum federation token duration is 12 hours")
		return
	}

	if input.Config.RoleARN == "" {
		input.Config.NoSession = true
	}

	err := configLoader.LoadFromProfile(input.ProfileName, &input.Config)
	if err != nil {
		app.Fatalf("%v", err)
	}

	creds, err := vault.NewTempCredentials(input.Keyring, &input.Config)
	if err != nil {
		app.Fatalf("%v", err)
	}

	val, err := creds.Get()
	if err != nil {
		app.Fatalf(FormatCredentialError(err, input.Config.CredentialsName))
	}

	isFederated := false

	// if AssumeRole isn't used, GetFederationToken has to be used for IAM credentials
	if val.SessionToken == "" {
		log.Printf("No session token found, calling GetFederationToken")
		stsCreds, err := getFederationToken(val, input.FederationTokenDuration, input.Config.Region)
		if err != nil {
			app.Fatalf("Failed to call GetFederationToken: %v\n"+
				"Login for non-assumed roles depends on permission to call sts:GetFederationToken", err)
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

	loginURLPrefix, destination := generateLoginURL(input.Config.Region, input.Path)

	req, err := http.NewRequest("GET", loginURLPrefix, nil)
	if err != nil {
		app.Fatalf("%v", err)
		return
	}

	log.Printf("Creating login token, expires in %s", input.FederationTokenDuration)

	q := req.URL.Query()
	q.Add("Action", "getSigninToken")
	q.Add("Session", string(jsonBytes))

	// not needed for federation tokens
	if input.Config.NoSession && !isFederated {
		q.Add("SessionDuration", fmt.Sprintf("%.f", input.FederationTokenDuration.Seconds()))
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

	loginURL := fmt.Sprintf(
		"%s?Action=login&Issuer=aws-vault&Destination=%s&SigninToken=%s",
		loginURLPrefix,
		url.QueryEscape(destination),
		url.QueryEscape(signinToken),
	)

	if input.UseStdout {
		fmt.Println(loginURL)
	} else if err = open.Run(loginURL); err != nil {
		log.Println(err)
		fmt.Println(loginURL)
	}
}

func getFederationToken(creds credentials.Value, d time.Duration, region string) (*sts.Credentials, error) {
	sess := session.Must(session.NewSession(aws.NewConfig().WithCredentials(credentials.NewStaticCredentialsFromCreds(creds)).WithRegion(region)))
	client := sts.New(sess)

	currentUsername, err := vault.GetUsernameFromSession(sess)
	if err != nil {
		return nil, err
	}

	// truncate the username if it's longer than 32 characters or else GetFederationToken will fail. see: https://docs.aws.amazon.com/STS/latest/APIReference/API_GetFederationToken.html
	if len(currentUsername) > 32 {
		currentUsername = currentUsername[0:32]
	}

	params := &sts.GetFederationTokenInput{
		Name:            aws.String(currentUsername),
		DurationSeconds: aws.Int64(int64(d.Seconds())),
		Policy:          aws.String(allowAllIAMPolicy),
	}

	resp, err := client.GetFederationToken(params)
	if err != nil {
		return nil, err
	}

	return resp.Credentials, nil
}

func generateLoginURL(region string, path string) (string, string) {
	loginURLPrefix := "https://signin.aws.amazon.com/federation"
	destination := "https://console.aws.amazon.com/"

	if region != "" {
		destinationDomain := "console.aws.amazon.com"
		switch {
		case strings.HasPrefix(region, "cn-"):
			loginURLPrefix = "https://signin.amazonaws.cn/federation"
			destinationDomain = "console.amazonaws.cn"
		case strings.HasPrefix(region, "us-gov-"):
			loginURLPrefix = "https://signin.amazonaws-us-gov.com/federation"
			destinationDomain = "console.amazonaws-us-gov.com"
		}
		if path != "" {
			destination = fmt.Sprintf(
				"https://%s.%s/%s?region=%s",
				region, destinationDomain, path, region,
			)
		} else {
			destination = fmt.Sprintf(
				"https://%s.%s/console/home?region=%s",
				region, destinationDomain, region,
			)
		}
	}
	return loginURLPrefix, destination
}
