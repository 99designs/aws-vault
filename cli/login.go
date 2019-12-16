package cli

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/99designs/aws-vault/vault"
	"github.com/99designs/keyring"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/skratchdot/open-golang/open"
	"gopkg.in/alecthomas/kingpin.v2"
)

const allowAllIAMPolicy = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`

type LoginCommandInput struct {
	ProfileName     string
	Keyring         keyring.Keyring
	UseStdout       bool
	Path            string
	Config          vault.Config
	SessionDuration time.Duration
}

func ConfigureLoginCommand(app *kingpin.Application) {
	input := LoginCommandInput{}

	cmd := app.Command("login", "Generate a login link for the AWS Console")

	cmd.Flag("duration", "Duration of the assume-role or federated session. Defaults to 1h").
		Short('d').
		DurationVar(&input.SessionDuration)

	cmd.Flag("mfa-token", "The MFA token to use").
		Short('t').
		StringVar(&input.Config.MfaToken)

	cmd.Flag("path", "The AWS service you would like access").
		StringVar(&input.Path)

	cmd.Flag("stdout", "Print login URL to stdout instead of opening in default browser").
		Short('s').
		BoolVar(&input.UseStdout)

	cmd.Arg("profile", "Name of the profile").
		Required().
		HintAction(awsConfigFile.ProfileNames).
		StringVar(&input.ProfileName)

	cmd.Action(func(c *kingpin.ParseContext) error {
		input.Config.MfaPromptMethod = GlobalFlags.PromptDriver
		input.Config.GetSessionTokenDuration = input.SessionDuration
		input.Config.AssumeRoleDuration = input.SessionDuration
		input.Keyring = keyringImpl
		LoginCommand(app, input)
		return nil
	})
}

const DefaultFederationTokenDuration = 1 * time.Hour

func getFederationTokenDuration(input LoginCommandInput) time.Duration {
	if input.SessionDuration != 0 {
		return input.SessionDuration
	}

	d, err := time.ParseDuration(os.Getenv("AWS_FEDERATION_TOKEN_TTL"))
	if err == nil {
		log.Printf("Using a session duration of %q from AWS_FEDERATION_TOKEN_TTL", d)
		return d
	}

	return DefaultFederationTokenDuration
}

func LoginCommand(app *kingpin.Application, input LoginCommandInput) {
	federationTokenDuration := getFederationTokenDuration(input)

	err := configLoader.LoadFromProfile(input.ProfileName, &input.Config)
	if err != nil {
		app.Fatalf("%v", err)
	}

	// if AssumeRole isn't used, GetFederationToken has to be used for IAM credentials
	isFederated := (input.Config.RoleARN == "")

	// Only federation tokens or assume role tokens may be used for federated login (not session tokens)
	if isFederated {
		input.Config.NoSession = true
	}

	creds, err := vault.NewCredentials(input.Keyring, input.Config)
	if err != nil {
		app.Fatalf("%v", err)
	}

	type SessionData struct {
		SessionId    string `json:"sessionId"`
		SessionKey   string `json:"sessionKey"`
		SessionToken string `json:"sessionToken"`
		expiration   time.Time
	}

	sess := SessionData{}
	if isFederated {
		log.Printf("No session token found, calling GetFederationToken")
		s := session.Must(session.NewSession(aws.NewConfig().WithRegion(input.Config.Region).WithCredentials(creds)))
		stsCreds, err := getFederationToken(s, federationTokenDuration)
		if err != nil {
			app.Fatalf("Failed to call GetFederationToken: %v", err)
			return
		}
		sess.SessionId = *stsCreds.AccessKeyId
		sess.SessionKey = *stsCreds.SecretAccessKey
		sess.SessionToken = *stsCreds.SessionToken
		sess.expiration = *stsCreds.Expiration
	} else {
		val, err := creds.Get()
		if err != nil {
			app.Fatalf(FormatCredentialError(err, input.Config.CredentialsName))
		}
		sess.SessionId = val.AccessKeyID
		sess.SessionKey = val.SecretAccessKey
		sess.SessionToken = val.SessionToken
		sess.expiration, _ = creds.ExpiresAt()
	}

	sessionDataJSON, err := json.Marshal(sess)
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

	log.Printf("Creating login token, expires in %s", time.Until(sess.expiration))

	q := req.URL.Query()
	q.Add("Action", "getSigninToken")
	q.Add("Session", string(sessionDataJSON))
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

	loginURL := fmt.Sprintf("%s?Action=login&Issuer=aws-vault&Destination=%s&SigninToken=%s",
		loginURLPrefix, url.QueryEscape(destination), url.QueryEscape(signinToken))

	if input.UseStdout {
		fmt.Println(loginURL)
	} else if err = open.Run(loginURL); err != nil {
		log.Println(err)
		fmt.Println(loginURL)
	}
}

func getFederationToken(s *session.Session, federationTokenDuration time.Duration) (*sts.Credentials, error) {
	client := sts.New(s)

	currentUsername, err := vault.GetUsernameFromSession(s)
	if err != nil {
		return nil, err
	}

	// truncate the username if it's longer than 32 characters or else GetFederationToken will fail. see: https://docs.aws.amazon.com/STS/latest/APIReference/API_GetFederationToken.html
	if len(currentUsername) > 32 {
		currentUsername = currentUsername[0:32]
	}

	params := &sts.GetFederationTokenInput{
		Name:            aws.String(currentUsername),
		DurationSeconds: aws.Int64(int64(federationTokenDuration.Seconds())),
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
			destination = fmt.Sprintf("https://%s.%s/%s?region=%s",
				region, destinationDomain, path, region)
		} else {
			destination = fmt.Sprintf("https://%s.%s/console/home?region=%s",
				region, destinationDomain, region)
		}
	}
	return loginURLPrefix, destination
}
