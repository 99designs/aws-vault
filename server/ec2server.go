package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/99designs/aws-vault/v7/iso8601"
	"github.com/aws/aws-sdk-go-v2/aws"
)

const ec2CredentialsServerAddr = "127.0.0.1:9099"

// StartEc2CredentialsServer starts a EC2 Instance Metadata server and endpoint proxy
func StartEc2CredentialsServer(ctx context.Context, credsProvider aws.CredentialsProvider, region string) error {
	credsCache := aws.NewCredentialsCache(credsProvider)

	// pre-fetch credentials so that we can respond quickly to the first request
	// SDKs seem to very aggressively timeout
	_, _ = credsCache.Retrieve(ctx)

	go startEc2CredentialsServer(credsCache, region)

	return nil
}

func startEc2CredentialsServer(credsProvider aws.CredentialsProvider, region string) {
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
	router.HandleFunc("/latest/dynamic/instance-identity/document", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"region": "`+region+`"}`)
	})

	router.HandleFunc("/latest/meta-data/iam/security-credentials/local-credentials", credsHandler(credsProvider))

	log.Fatalln(http.ListenAndServe(ec2CredentialsServerAddr, withLogging(withSecurityChecks(router))))
}

// withSecurityChecks is middleware to protect the server from attack vectors
func withSecurityChecks(next *http.ServeMux) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Check the remote ip is from the loopback, otherwise clients on the same network segment could
		// potentially route traffic via 169.254.169.254:80
		// See https://developer.apple.com/library/content/qa/qa1357/_index.html
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if !net.ParseIP(ip).IsLoopback() {
			http.Error(w, "Access denied from non-localhost address", http.StatusUnauthorized)
			return
		}

		// Check that the request is to 169.254.169.254
		// Without this it's possible for an attacker to mount a DNS rebinding attack
		// See https://github.com/99designs/aws-vault/issues/578
		if r.Host != ec2MetadataEndpointIP && r.Host != ec2MetadataEndpointAddr {
			http.Error(w, fmt.Sprintf("Access denied for host '%s'", r.Host), http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	}
}

func credsHandler(credsProvider aws.CredentialsProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		creds, err := credsProvider.Retrieve(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusGatewayTimeout)
			return
		}

		log.Printf("Serving credentials via http ****************%s, expiration of %s (%s)",
			creds.AccessKeyID[len(creds.AccessKeyID)-4:],
			creds.Expires.Format(time.RFC3339),
			time.Until(creds.Expires).String())

		err = json.NewEncoder(w).Encode(map[string]interface{}{
			"Code":            "Success",
			"LastUpdated":     iso8601.Format(time.Now()),
			"Type":            "AWS-HMAC",
			"AccessKeyId":     creds.AccessKeyID,
			"SecretAccessKey": creds.SecretAccessKey,
			"Token":           creds.SessionToken,
			"Expiration":      iso8601.Format(creds.Expires),
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
}
