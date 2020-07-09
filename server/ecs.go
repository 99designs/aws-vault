package server

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go/aws/credentials"
)

func writeErrorMessage(w http.ResponseWriter, msg string, statusCode int) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(map[string]string{"Message": msg}); err != nil {
		log.Println(err.Error())
	}
}

func withAuthorizationCheck(token string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != token {
			writeErrorMessage(w, "invalid Authorization token", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	}
}

// StartEcsCredentialServer starts an ECS credential server on a random port
func StartEcsCredentialServer(creds *credentials.Credentials, minValidDuration time.Duration) (string, string, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", "", err
	}
	token, err := generateRandomString()
	if err != nil {
		return "", "", err
	}

	go func() {
		err := http.Serve(listener, withLogging(withAuthorizationCheck(token, ecsCredsHandler(creds, minValidDuration))))
		// returns ErrServerClosed on graceful close
		if err != http.ErrServerClosed {
			log.Fatalf("ecs server: %s", err.Error())
		}
	}()

	uri := fmt.Sprintf("http://%s", listener.Addr().String())
	return uri, token, nil
}

func ecsCredsHandler(creds *credentials.Credentials, minValidDuration time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		val, err := creds.Get()
		if err != nil {
			writeErrorMessage(w, err.Error(), http.StatusInternalServerError)
			return
		}

		credsExpiresAt, err := creds.ExpiresAt()
		if err != nil {
			writeErrorMessage(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if time.Until(credsExpiresAt) < minValidDuration {
			log.Printf("Forcing expiration of credentials due to minValidDuration (%s)",
				time.Until(credsExpiresAt).String())
			creds.Expire()

			val, err = creds.Get()
			if err != nil {
				writeErrorMessage(w, err.Error(), http.StatusInternalServerError)
				return
			}

			credsExpiresAt, err = creds.ExpiresAt()
			if err != nil {
				writeErrorMessage(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}

		err = json.NewEncoder(w).Encode(map[string]string{
			"AccessKeyId":     val.AccessKeyID,
			"SecretAccessKey": val.SecretAccessKey,
			"Token":           val.SessionToken,
			"Expiration":      credsExpiresAt.Format(time.RFC3339),
		})
		if err != nil {
			writeErrorMessage(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
}

func generateRandomString() (string, error) {
	b := make([]byte, 30)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
