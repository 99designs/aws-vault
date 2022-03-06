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

type EcsServer struct {
	listener      net.Listener
	credsProvider aws.CredentialsProvider
	config        *vault.Config
	authToken     string
}

func NewEcsServer(credsProvider aws.CredentialsProvider, config *vault.Config, authToken string, port int) (*EcsServer, error) {
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return nil, err
	}
	if authToken == "" {
		authToken = generateRandomString()
	}

	return &EcsServer{
		listener:      listener,
		credsProvider: credsProvider,
		config:        config,
		authToken:     authToken,
	}, nil
}

func (e *EcsServer) BaseUrl() string {
	return fmt.Sprintf("http://%s", e.listener.Addr().String())
}
func (e *EcsServer) AuthToken() string {
	return e.authToken
}

func (e *EcsServer) Start() error {
	credsCache := aws.NewCredentialsCache(e.credsProvider)

	// Retrieve credentials eagerly to support MFA prompts
	_, err := credsCache.Retrieve(context.TODO())
	if err != nil {
		return fmt.Errorf("Retrieving base creds: %w", err)
	}

	router := http.NewServeMux()

	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		creds, err := credsCache.Retrieve(r.Context())
		if err != nil {
			writeErrorMessage(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeCredsToResponse(creds, w)
	})

	router.HandleFunc("/role-arn/", func(w http.ResponseWriter, r *http.Request) {
		roleArn := strings.TrimPrefix(r.URL.Path, "/role-arn/")
		cfg := vault.NewAwsConfigWithCredsProvider(credsCache, e.config.Region, e.config.STSRegionalEndpoints)
		roleProvider := &vault.AssumeRoleProvider{
			StsClient: sts.NewFromConfig(cfg),
			RoleARN:   roleArn,
			Duration:  e.config.AssumeRoleDuration,
		}

		creds, err := roleProvider.Retrieve(r.Context())
		if err != nil {
			writeErrorMessage(w, err.Error(), http.StatusInternalServerError)
			return
		}

		writeCredsToResponse(creds, w)
	})

	return http.Serve(e.listener, withLogging(withAuthorizationCheck(e.authToken, router.ServeHTTP)))
}
