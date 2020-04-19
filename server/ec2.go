package server

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/aws/aws-sdk-go/aws/credentials"
)

const (
	awsTimeFormat            = "2006-01-02T15:04:05Z"
	ec2MetadataEndpointAddr  = "169.254.169.254:80"
	ec2CredentialsServerAddr = "127.0.0.1:9099"
)

// StartEc2MetadataEndpointProxy starts a http proxy server on the standard EC2 Instance Metadata endpoint
func StartEc2MetadataEndpointProxy() error {
	var localServerURL, err = url.Parse(fmt.Sprintf("http://%s/", ec2CredentialsServerAddr))
	if err != nil {
		log.Fatal(err)
	}

	if _, err := installEc2EndpointNetworkAlias(); err != nil {
		return err
	}

	l, err := net.Listen("tcp", ec2MetadataEndpointAddr)
	if err != nil {
		return err
	}

	log.Printf("EC2 Instance Metadata endpoint proxy server running on %s", l.Addr())
	return http.Serve(l, httputil.NewSingleHostReverseProxy(localServerURL))
}

func isServerRunning(bind string) bool {
	_, err := net.DialTimeout("tcp", bind, time.Millisecond*10)
	return err == nil
}

// StartEc2CredentialsServer starts a EC2 Instance Metadata server and endpoint proxy
func StartEc2CredentialsServer(creds *credentials.Credentials, region string) error {
	if !isServerRunning(ec2MetadataEndpointAddr) {
		if err := StartEc2EndpointProxyServerProcess(); err != nil {
			return err
		}
	}

	// pre-fetch credentials so that we can respond quickly to the first request
	_, _ = creds.Get()

	go startEc2CredentialsServer(creds, region)

	return nil
}

func startEc2CredentialsServer(creds *credentials.Credentials, region string) {

	log.Printf("Starting EC2 Instance Metadata server on %s", ec2CredentialsServerAddr)
	router := http.NewServeMux()

	router.HandleFunc("/latest/meta-data/iam/security-credentials/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "local-credentials")
	})

	// The AWS Go SDK checks the instance-id endpoint to validate the existence of EC2 Metadata
	router.HandleFunc("/latest/meta-data/instance-id/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "aws-vault")
	})

	// The AWS .NET SDK checks this endpoint during obtaining credentials/refreshing them
	router.HandleFunc("/latest/meta-data/iam/info/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"Code" : "Success"}`)
	})

	// used by AWS SDK to determine region
	router.HandleFunc("/latest/meta-data/dynamic/instance-identity/document", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"region": "`+region+`"}`)
	})

	router.HandleFunc("/latest/meta-data/iam/security-credentials/local-credentials", credsHandler(creds))

	log.Fatalln(http.ListenAndServe(ec2CredentialsServerAddr, logRequest(withLoopbackSecurityCheck(router))))
}

// withLoopbackSecurityCheck is middleware to check that the request comes from the loopback device
// We must make sure the remote ip is from the loopback, otherwise clients on the same network segment could
// potentially route traffic via 169.254.169.254:80
// See https://developer.apple.com/library/content/qa/qa1357/_index.html
func withLoopbackSecurityCheck(next *http.ServeMux) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if !net.ParseIP(ip).IsLoopback() {
			http.Error(w, "Access denied from non-localhost address", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	}
}

func credsHandler(creds *credentials.Credentials) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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
