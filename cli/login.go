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

	"github.com/99designs/aws-vault/vault"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/skratchdot/open-golang/open"
	"gopkg.in/alecthomas/kingpin.v2"
)

type LoginCommandInput struct {
	ProfileName     string
	Keyring         *vault.CredentialKeyring
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
		input.Config.GetFederationTokenDuration = input.SessionDuration
		input.Keyring = &vault.CredentialKeyring{Keyring: keyringImpl}
		err := LoginCommand(input)
		app.FatalIfError(err, "Login failed")
		return nil
	})
}

func LoginCommand(input LoginCommandInput) error {
	configLoader.BaseConfig = input.Config
	configLoader.ActiveProfile = input.ProfileName
	config, err := configLoader.LoadFromProfile(input.ProfileName)
	if err != nil {
		return err
	}

	var creds *credentials.Credentials

	// if AssumeRole isn't used, GetFederationToken has to be used for IAM credentials
	if config.RoleARN == "" {
		creds, err = vault.NewFederationTokenCredentials(input.ProfileName, input.Keyring, config)
	} else {
		creds, err = vault.NewTempCredentials(config, input.Keyring)
	}
	if err != nil {
		return err
	}

	val, err := creds.Get()
	if err != nil {
		return fmt.Errorf("Failed to get credentials for %s: %w", config.ProfileName, err)
	}

	jsonBytes, err := json.Marshal(map[string]string{
		"sessionId":    val.AccessKeyID,
		"sessionKey":   val.SecretAccessKey,
		"sessionToken": val.SessionToken,
	})
	if err != nil {
		return err
	}

	loginURLPrefix, destination := generateLoginURL(config.Region, input.Path)

	req, err := http.NewRequest("GET", loginURLPrefix, nil)
	if err != nil {
		return err
	}

	if expiration, err := creds.ExpiresAt(); err != nil {
		log.Printf("Creating login token, expires in %s", time.Until(expiration))
	}

	q := req.URL.Query()
	q.Add("Action", "getSigninToken")
	q.Add("Session", string(jsonBytes))
	req.URL.RawQuery = q.Encode()

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		log.Printf("Response body was %s", body)
		return fmt.Errorf("Call to getSigninToken failed with %v", resp.Status)
	}

	var respParsed map[string]string

	err = json.Unmarshal([]byte(body), &respParsed)
	if err != nil {
		return err
	}

	signinToken, ok := respParsed["SigninToken"]
	if !ok {
		return fmt.Errorf("Expected a response with SigninToken")
	}

	loginURL := fmt.Sprintf("%s?Action=login&Issuer=aws-vault&Destination=%s&SigninToken=%s",
		loginURLPrefix, url.QueryEscape(destination), url.QueryEscape(signinToken))

	if input.UseStdout {
		fmt.Println(loginURL)
	} else if err = open.Run(loginURL); err != nil {
		log.Println(err)
		fmt.Println(loginURL)
	}

	return nil
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
