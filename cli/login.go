package cli

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
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
	Profile                 string
	Keyring                 keyring.Keyring
	MfaToken                string
	MfaPrompt               prompt.PromptFunc
	UseStdout               bool
	FederationTokenDuration time.Duration
	AssumeRoleDuration      time.Duration
	Service                 string
}

func ConfigureLoginCommand(app *kingpin.Application) {
	input := LoginCommandInput{}

	cmd := app.Command("login", "Generate a login link for the AWS Console")
	cmd.Arg("profile", "Name of the profile").
		Required().
		StringVar(&input.Profile)

	cmd.Flag("mfa-token", "The mfa token to use").
		Short('t').
		StringVar(&input.MfaToken)

	cmd.Flag("service", "The AWS service you would like access").
		Short('t').
		StringVar(&input.Service)

	cmd.Flag("federation-token-ttl", "Expiration time for aws console session").
		Default("12h").
		OverrideDefaultFromEnvar("AWS_FEDERATION_TOKEN_TTL").
		Short('f').
		DurationVar(&input.FederationTokenDuration)

	cmd.Flag("assume-role-ttl", "Expiration time for aws assumed role").
		Default("15m").
		DurationVar(&input.AssumeRoleDuration)

	cmd.Flag("stdout", "Print login URL to stdout instead of opening in default browser").
		Short('s').
		BoolVar(&input.UseStdout)

	cmd.Action(func(c *kingpin.ParseContext) error {
		input.MfaPrompt = prompt.Method(GlobalFlags.PromptDriver)
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

	provider, err := vault.NewVaultProvider(input.Keyring, input.Profile, vault.VaultOptions{
		AssumeRoleDuration: input.AssumeRoleDuration,
		MfaToken:           input.MfaToken,
		MfaPrompt:          input.MfaPrompt,
		Service:            input.Service
		NoSession:          true,
		Config:             awsConfig,
	})
	if err != nil {
		app.Fatalf("Failed to create vault provider: %v", err)
		return
	}

	creds := credentials.NewCredentials(provider)
	val, err := creds.Get()
	if err != nil {
		app.Fatalf(awsConfig.FormatCredentialError(err, input.Profile))
	}

	var isFederated bool
	var sessionDuration = input.FederationTokenDuration

	// if AssumeRole isn't used, GetFederationToken has to be used for IAM credentials
	if val.SessionToken == "" {
		log.Printf("No session token found, calling GetFederationToken")
		stsCreds, err := getFederationToken(val, input.FederationTokenDuration)
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

  if input.Service != "" {
  	destination = fmt.Sprintf(
  			"https://console.aws.amazon.com/%s",
  			input.Service,
  		)
	  } else {
  	destination := "https://console.aws.amazon.com/"
  	if profile, _ := awsConfig.Profile(input.Profile); profile.Region != "" {
  		destination = fmt.Sprintf(
  			"https://%s.console.aws.amazon.com/console/home?region=%s",
  			profile.Region, profile.Region,
  		)
  	}
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

func getFederationToken(creds credentials.Value, d time.Duration) (*sts.Credentials, error) {
	sess := session.New(&aws.Config{
		Credentials: credentials.NewCredentials(&credentials.StaticProvider{Value: creds}),
	})
	client := sts.New(sess)

	currentUsername, err := vault.GetUsernameFromSession(sess)
	if err != nil {
		return nil, err
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
