package server

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	ec2MetadataEndpointIP   = "169.254.169.254"
	ec2MetadataEndpointAddr = "169.254.169.254:80"
)

// StartProxy starts a http proxy server that listens on the standard EC2 Instance Metadata endpoint http://169.254.169.254:80/
// and forwards requests through to the running `aws-vault exec` command
func StartProxy() error {
	var localServerURL, err = url.Parse(fmt.Sprintf("http://%s/", ec2CredentialsServerAddr))
	if err != nil {
		return err
	}

	if output, err := installEc2EndpointNetworkAlias(); err != nil {
		return fmt.Errorf("%s: %s", strings.TrimSpace(string(output)), err.Error())
	}

	l, err := net.Listen("tcp", ec2MetadataEndpointAddr)
	if err != nil {
		return err
	}

	handler := http.NewServeMux()
	handler.HandleFunc("/stop", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		go Shutdown()
	})
	handler.Handle("/", httputil.NewSingleHostReverseProxy(localServerURL))

	log.Printf("EC2 Instance Metadata endpoint proxy server running on %s", l.Addr())
	return http.Serve(l, handler)
}

func isProxyRunning() bool {
	_, err := net.DialTimeout("tcp", ec2MetadataEndpointAddr, time.Millisecond*10)
	return err == nil
}

func Shutdown() {
	_, err := removeEc2EndpointNetworkAlias()
	if err != nil {
		log.Fatalln(err)
	}
	os.Exit(0)
}

// StopProxy stops the http proxy server on the standard EC2 Instance Metadata endpoint
func StopProxy() {
	_, _ = http.Get(fmt.Sprintf("http://%s/stop", ec2MetadataEndpointAddr))
}

func awsVaultExecutable() string {
	awsVaultPath, err := os.Executable()
	if err != nil {
		return awsVaultPath
	}

	return os.Args[0]
}
