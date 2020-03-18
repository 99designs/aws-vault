package server

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/99designs/aws-vault/vault"
	"github.com/aws/aws-sdk-go/aws/credentials"
)

const (
	metadataBind               = "169.254.169.254:80"
	awsTimeFormat              = "2006-01-02T15:04:05Z"
	identityDocumentServerURL  = "http://127.0.0.1:9098"
	identityDocumentServerBind = "127.0.0.1:9098"
	credentialServerURL        = "http://127.0.0.1:9099"
	credentialServerBind       = "127.0.0.1:9099"
)

func StartMetadataServer() error {
	if _, err := installNetworkAlias(); err != nil {
		return err
	}

	router := http.NewServeMux()
	router.HandleFunc("/latest/meta-data/iam/security-credentials/", indexHandler)
	router.HandleFunc("/latest/meta-data/iam/security-credentials/local-credentials", credentialsHandler)
	router.HandleFunc("/latest/meta-data/dynamic/instance-identity/document", identityDocumentHandler)
	// The AWS Go SDK checks the instance-id endpoint to validate the existence of EC2 Metadata
	router.HandleFunc("/latest/meta-data/instance-id/", instanceIdHandler)
	// The AWS .NET SDK checks this endpoint during obtaining credentials/refreshing them
	router.HandleFunc("/latest/meta-data/iam/info/", infoHandlerStub)

	l, err := net.Listen("tcp", metadataBind)
	if err != nil {
		return err
	}

	log.Printf("Local instance role server running on %s", l.Addr())
	return http.Serve(l, router)
}

func infoHandlerStub(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, `{"Code" : "Success"}`)
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "local-credentials")
}

func identityDocumentHandler(w http.ResponseWriter, r *http.Request) {
	resp, err := http.Get(identityDocumentServerURL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusGatewayTimeout)
		return
	}
	defer resp.Body.Close()

	log.Printf("Fetched identity document from %s", identityDocumentServerURL)

	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)

	_, err = io.Copy(w, resp.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func credentialsHandler(w http.ResponseWriter, r *http.Request) {
	resp, err := http.Get(credentialServerURL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusGatewayTimeout)
		return
	}
	defer resp.Body.Close()

	log.Printf("Fetched credentials from %s", credentialServerURL)

	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)

	_, err = io.Copy(w, resp.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func instanceIdHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "aws-vault")
}

func checkServerRunning(bind string) bool {
	_, err := net.DialTimeout("tcp", bind, time.Millisecond*10)
	return err == nil
}

func StartIdentityDocumentServer(config *vault.Config) error {
	if !checkServerRunning(metadataBind) {
		if err := StartCredentialProxy(); err != nil {
			return err
		}
	}

	log.Printf("Starting local instance document server on %s", identityDocumentServerBind)
	go func() {
		log.Fatalln(http.ListenAndServe(identityDocumentServerBind, identityDocHandler(config)))
	}()

	return nil
}

func identityDocHandler(config *vault.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		err := json.NewEncoder(w).Encode(map[string]interface{}{
			"region": config.Region,
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
}

func StartCredentialsServer(creds *credentials.Credentials) error {
	if !checkServerRunning(metadataBind) {
		if err := StartCredentialProxy(); err != nil {
			return err
		}
	}

	log.Printf("Starting local instance role server on %s", credentialServerBind)
	go func() {
		log.Fatalln(http.ListenAndServe(credentialServerBind, credsHandler(creds)))
	}()

	return nil
}

func credsHandler(creds *credentials.Credentials) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Must make sure the remote ip is from the loopback, otherwise clients on the same network segment could
		// potentially route traffic via 169.254.169.254:80
		// See https://developer.apple.com/library/content/qa/qa1357/_index.html
		if !net.ParseIP(ip).IsLoopback() {
			http.Error(w, "Access denied from non-localhost address", http.StatusUnauthorized)
			return
		}

		log.Printf("RemoteAddr = %v", r.RemoteAddr)
		log.Printf("Credentials.IsExpired() = %#v", creds.IsExpired())

		val, err := creds.Get()
		if err != nil {
			http.Error(w, err.Error(), http.StatusGatewayTimeout)
			return
		}
		credsExpiresAt, err := creds.ExpiresAt()
		if err != nil {
			http.Error(w, err.Error(), http.StatusGatewayTimeout)
			return
		}

		log.Printf("Serving credentials via http ****************%s, expiration of %s (%s)",
			val.AccessKeyID[len(val.AccessKeyID)-4:],
			credsExpiresAt.Format(awsTimeFormat),
			time.Until(credsExpiresAt).String())

		err = json.NewEncoder(w).Encode(map[string]interface{}{
			"Code":            "Success",
			"LastUpdated":     time.Now().Format(awsTimeFormat),
			"Type":            "AWS-HMAC",
			"AccessKeyId":     val.AccessKeyID,
			"SecretAccessKey": val.SecretAccessKey,
			"Token":           val.SessionToken,
			"Expiration":      credsExpiresAt.Format(awsTimeFormat),
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
}
