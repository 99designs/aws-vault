package server

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/99designs/aws-vault/vault"
	"log"
	"net"
	"net/http"
)

type EcsCredentialServer struct {
	Url           string
	Authorization string
}

type EcsCredentialData struct {
	AccessKeyID     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	SessionToken    string `json:"Token"`
	Expiration      string `json:"Expiration"`
}

type EcsCredentialError struct {
	Message string `json:"message"`
}

func StartEcsCredentialServer(creds *vault.VaultCredentials) (*EcsCredentialServer, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	token, err := GenerateToken(16)
	if err != nil {
		return nil, err
	}
	srv := &http.Server{Addr: listener.Addr().String()}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == token {
			body, err := getResponse(creds)
			if err != nil {
				body, err = json.Marshal(&EcsCredentialError{Message: err.Error()})
				if err != nil {
					log.Fatalf("Failed to serialize err: %s", err)
				}
			}
			w.Write(body)
		} else {
			w.WriteHeader(http.StatusForbidden)
			body, err := json.Marshal(&EcsCredentialError{Message: "invalid Authorization token"})
			if err != nil {
				log.Fatalf("Failed to serialize err: %s", err)
			}
			w.Write(body)
		}
	})

	go func() {
		// returns ErrServerClosed on graceful close
		if err := srv.Serve(listener); err != http.ErrServerClosed {
			log.Fatalf("Serve(): %s", err)
		}
	}()

	return &EcsCredentialServer{
		Authorization: token,
		Url:           fmt.Sprintf("http://%s", listener.Addr().String()),
	}, nil
}

func getResponse(creds *vault.VaultCredentials) ([]byte, error) {
	val, err := creds.Get()
	if err != nil {
		return nil, err
	}
	ecsCredential := &EcsCredentialData{
		AccessKeyID:     val.AccessKeyID,
		SecretAccessKey: val.SecretAccessKey,
		SessionToken:    val.SessionToken,
		Expiration:      creds.Expires().Format("2006-01-02T15:04:05Z"),
	}
	serialized, err := json.Marshal(&ecsCredential)
	if err != nil {
		return nil, err
	}
	return serialized, nil
}

func GenerateToken(bytes int) (string, error) {
	b, err := GenerateRandomBytes(bytes)
	return base64.RawURLEncoding.EncodeToString(b), err
}

func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}
