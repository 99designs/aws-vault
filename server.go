package main

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
)

const (
	metadataBind    = "169.254.169.254:80"
	awsTimeFormat   = "2006-01-02T15:04:05Z"
	localServerUrl  = "http://127.0.0.1:9099"
	localServerBind = "127.0.0.1:9099"
)

type ServerCommandInput struct {
}

func ServerCommand(ui Ui, input ServerCommandInput) {
	if output, err := installNetworkAlias(); err != nil {
		ui.Error.Println(string(output))
		ui.Error.Fatal(err)
	}

	router := http.NewServeMux()
	router.HandleFunc("/latest/meta-data/iam/security-credentials/", indexHandler)
	router.HandleFunc("/latest/meta-data/iam/security-credentials/local-credentials", credentialsHandler)

	l, err := net.Listen("tcp", metadataBind)
	if err != nil {
		ui.Error.Fatal(err)
	}

	ui.Debug.Printf("Local instance role server running on %s", l.Addr())
	ui.Println(http.Serve(l, router))
}

type metadataHandler struct {
	http.Handler
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s", r.Method, r.RequestURI)

	fmt.Fprintf(w, "local-credentials")
}

func credentialsHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s", r.Method, r.RequestURI)

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

func installNetworkAlias() ([]byte, error) {
	return exec.Command("ifconfig", "lo0", "alias", "169.254.169.254").CombinedOutput()
}

func checkServerRunning(bind string) bool {
	_, err := net.DialTimeout("tcp", bind, time.Millisecond*10)
	return err == nil
}

func startCredentialsServer(ui Ui, creds *VaultCredentials) error {
	if !checkServerRunning(metadataBind) {
		ui.Error.Println("Starting `aws-vault server` as root in the background")
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
		val, err := creds.Get()
		if err != nil {
			http.Error(w, err.Error(), http.StatusGatewayTimeout)
			return
		}

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
