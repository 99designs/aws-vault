package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/99designs/aws-vault/v6/iso8601"
	"github.com/99designs/aws-vault/v6/vault"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

func writeErrorMessage(w http.ResponseWriter, msg string, statusCode int) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(map[string]string{"Message": msg}); err != nil {
		log.Println(err.Error())
	}
}

func withAuthorizationCheck(authToken string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != authToken {
			writeErrorMessage(w, "invalid Authorization token", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	}
}

// StartEcsCredentialServer starts an ECS credential server on a random port
func StartEcsCredentialServer(credsProvider aws.CredentialsProvider) (string, string, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", "", err
	}
	authToken := generateRandomString()
	credsCache := aws.NewCredentialsCache(credsProvider)

	// Retrieve credentials eagerly to support MFA prompts
	_, err = credsCache.Retrieve(context.Background())
	if err != nil {
		return "", "", err
	}

	go func() {
		err := http.Serve(listener, withLogging(withAuthorizationCheck(authToken, ecsCredsHandler(credsCache))))
		if err != http.ErrServerClosed { // ErrServerClosed is a graceful close
			log.Fatalf("ecs server: %s", err.Error())
		}
	}()

	uri := fmt.Sprintf("http://%s", listener.Addr().String())
	return uri, authToken, nil
}

func ecsCredsHandler(credsCache *aws.CredentialsCache) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		creds, err := credsCache.Retrieve(r.Context())
		if err != nil {
			writeErrorMessage(w, err.Error(), http.StatusInternalServerError)
			return
		}

		writeCredsToResponse(creds, w)
	}
}

func writeCredsToResponse(creds aws.Credentials, w http.ResponseWriter) {
	err := json.NewEncoder(w).Encode(map[string]string{
		"AccessKeyId":     creds.AccessKeyID,
		"SecretAccessKey": creds.SecretAccessKey,
		"Token":           creds.SessionToken,
		"Expiration":      iso8601.Format(creds.Expires),
	})
	if err != nil {
		writeErrorMessage(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func generateRandomString() string {
	b := make([]byte, 30)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func StartStandaloneEcsRoleCredentialServer(ctx context.Context, credsProvider aws.CredentialsProvider, config *vault.Config, authToken string, port int, roleDuration time.Duration) error {
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return err
	}

	if authToken == "" {
		authToken = generateRandomString()
	}

	credsCache := aws.NewCredentialsCache(credsProvider)

	// Retrieve credentials eagerly to support MFA prompts
	_, err = credsCache.Retrieve(ctx)
	if err != nil {
		return fmt.Errorf("Retrieving base creds: %w", err)
	}

	fmt.Println("Starting standalone ECS credential server.")
	fmt.Println("Set the following environment variables to use the ECS credential server:")
	fmt.Println("")
	fmt.Println("      AWS_CONTAINER_AUTHORIZATION_TOKEN=" + authToken)
	fmt.Printf("      AWS_CONTAINER_CREDENTIALS_FULL_URI=http://127.0.0.1:%d/role-arn/YOUR_ROLE_ARN\n", port)
	fmt.Println("")
	fmt.Println("If you wish to use AWS_CONTAINER_CREDENTIALS_RELATIVE_URI=/role-arn/YOUR_ROLE_ARN instead of AWS_CONTAINER_CREDENTIALS_FULL_URI, use a reverse proxy on http://169.254.170.2:80")
	fmt.Println("")

	router := http.NewServeMux()

	router.HandleFunc("/role-arn/", func(w http.ResponseWriter, r *http.Request) {
		roleArn := strings.TrimPrefix(r.URL.Path, "/role-arn/")
		cfg := vault.NewAwsConfigWithCredsProvider(credsCache, config.Region, config.STSRegionalEndpoints)
		roleProvider := &vault.AssumeRoleProvider{
			StsClient: sts.NewFromConfig(cfg),
			RoleARN:   roleArn,
			Duration:  roleDuration,
		}

		creds, err := roleProvider.Retrieve(ctx)
		if err != nil {
			writeErrorMessage(w, err.Error(), http.StatusInternalServerError)
			return
		}

		writeCredsToResponse(creds, w)
	})

	err = http.Serve(listener, withLogging(withAuthorizationCheck(authToken, router.ServeHTTP)))
	if err != http.ErrServerClosed {
		log.Fatalf("ecs server: %s", err.Error())
	}

	return nil
}
