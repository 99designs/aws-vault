package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os/exec"
)

const (
	metadataBind   = "169.254.169.254:80"
	awsTimeFormat  = "2006-01-02T15:04:05Z"
	localServerUrl = "http://127.0.0.1:9099"
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
