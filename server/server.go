package server

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"time"

	"github.com/99designs/aws-vault/vault"
)

const (
	metadataBind    = "169.254.169.254:80"
	awsTimeFormat   = "2006-01-02T15:04:05Z"
	localServerUrl  = "http://127.0.0.1:9099"
	localServerBind = "127.0.0.1:9099"
)

func StartMetadataServer() error {
	if _, err := installNetworkAlias(); err != nil {
		return err
	}

	router := http.NewServeMux()
	router.HandleFunc("/latest/meta-data/iam/security-credentials/", indexHandler)
	router.HandleFunc("/latest/meta-data/iam/security-credentials/local-credentials", credentialsHandler)
	// The AWS Go SDK checks the instance-id endpoint to validate the existence of EC2 Metadata
	router.HandleFunc("/latest/meta-data/instance-id/", instanceIdHandler)

	l, err := net.Listen("tcp", metadataBind)
	if err != nil {
		return err
	}

	log.Printf("Local instance role server running on %s", l.Addr())
	return http.Serve(l, router)
}

type metadataHandler struct {
	http.Handler
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "local-credentials")
}

func credentialsHandler(w http.ResponseWriter, r *http.Request) {
	resp, err := http.Get(localServerUrl)
	if err != nil {
		http.Error(w, err.Error(), http.StatusGatewayTimeout)
		return
	}
	defer resp.Body.Close()

	log.Printf("Fetched credentials from %s", localServerUrl)

	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)

	io.Copy(w, resp.Body)
}

func instanceIdHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "aws-vault")
}

func checkServerRunning(bind string) bool {
	_, err := net.DialTimeout("tcp", bind, time.Millisecond*10)
	return err == nil
}

func StartCredentialsServer(creds *vault.VaultCredentials) error {
	if !checkServerRunning(metadataBind) {
		log.Printf("Starting `aws-vault server` as root in the background")
		cmd := exec.Command("sudo", "-b", os.Args[0], "server")
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return err
		}
	}

	l, err := net.Listen("tcp", localServerBind)
	if err != nil {
		return err
	}

	log.Printf("Local instance role server running on %s", l.Addr())
	go http.Serve(l, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Credentials.IsExpired() = %#v", creds.IsExpired())

		val, err := creds.Get()
		if err != nil {
			http.Error(w, err.Error(), http.StatusGatewayTimeout)
			return
		}

		log.Printf("Serving credentials via http ****************%s, expiration of %s (%s)",
			val.AccessKeyID[len(val.AccessKeyID)-4:],
			creds.Expires().Format(awsTimeFormat),
			creds.Expires().Sub(time.Now()).String())

		json.NewEncoder(w).Encode(map[string]interface{}{
			"Code":            "Success",
			"LastUpdated":     time.Now().Format(awsTimeFormat),
			"Type":            "AWS-HMAC",
			"AccessKeyId":     val.AccessKeyID,
			"SecretAccessKey": val.SecretAccessKey,
			"Token":           val.SessionToken,
			"Expiration":      creds.Expires().Format(awsTimeFormat),
		})
	}))

	return nil
}
