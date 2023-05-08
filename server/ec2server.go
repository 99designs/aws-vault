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

const DefaultEc2CredentialsServerIp = "127.0.0.1"
const DefaultEc2CredentialsServerPort = "9099"
const DefaultEc2CredentialsServerAddr = DefaultEc2CredentialsServerIp + ":" + DefaultEc2CredentialsServerPort

type Ec2ServerParameters struct {
	region          string
	serverAddress   string
	allowedNetworks []net.IPNet
}

type Ec2ServerParameter interface {
	apply(*Ec2ServerParameters)
}

type ec2ServerAddress struct {
	serverAddress string
}

func (p *ec2ServerAddress) apply(params *Ec2ServerParameters) {
	params.serverAddress = p.serverAddress
}

func WithEc2ServerAddress(addr string) Ec2ServerParameter {
	return &ec2ServerAddress{serverAddress: addr}
}

type ec2ServerAllowedAddress struct {
	net net.IPNet
}

func (p *ec2ServerAllowedAddress) apply(params *Ec2ServerParameters) {
	params.allowedNetworks = append(params.allowedNetworks, p.net)
}

func WithEc2ServerAllowedNetwork(net net.IPNet) Ec2ServerParameter {
	return &ec2ServerAllowedAddress{net: net}
}

func NewEc2ServerParameters(region string, params ...Ec2ServerParameter) *Ec2ServerParameters {
	result := &Ec2ServerParameters{
		region:          region,
		serverAddress:   DefaultEc2CredentialsServerAddr,
		allowedNetworks: make([]net.IPNet, 0),
	}
	for _, p := range params {
		p.apply(result)
	}
	return result
}

// StartEc2CredentialsServer starts a EC2 Instance Metadata server and endpoint proxy
func StartEc2CredentialsServer(ctx context.Context, credsProvider aws.CredentialsProvider, params *Ec2ServerParameters) error {
	credsCache := aws.NewCredentialsCache(credsProvider)

	// pre-fetch credentials so that we can respond quickly to the first request
	// SDKs seem to very aggressively timeout
	_, _ = credsCache.Retrieve(ctx)

	go startEc2CredentialsServer(credsCache, params)

	return nil
}

func startEc2CredentialsServer(credsProvider aws.CredentialsProvider, params *Ec2ServerParameters) {
	log.Printf("Starting EC2 Instance Metadata server on %s", params.serverAddress)
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
		fmt.Fprintf(w, `{"region": "`+params.region+`"}`)
	})

	router.HandleFunc("/latest/meta-data/iam/security-credentials/local-credentials", credsHandler(credsProvider))

	log.Fatalln(http.ListenAndServe(params.serverAddress, withLogging(&withSecurityChecks{params, router})))
}

type withSecurityChecks struct {
	*Ec2ServerParameters
	next *http.ServeMux
}

// withSecurityChecks is middleware to protect the server from attack vectors
func (sc *withSecurityChecks) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Check the remote ip is from the loopback, otherwise clients on the same network segment could
	// potentially route traffic via 169.254.169.254:80
	// See https://developer.apple.com/library/content/qa/qa1357/_index.html
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	checkIp := func() bool {
		remoteIp := net.ParseIP(ip)
		if remoteIp == nil {
			return false
		}

		for _, allowedNetwork := range sc.allowedNetworks {
			if allowedNetwork.Contains(remoteIp) {
				return true
			}
		}

		return remoteIp.IsLoopback()
	}

	if !checkIp() {
		http.Error(w, "Access denied from not allowed address", http.StatusUnauthorized)
		return
	}

	// Check that the request is to 169.254.169.254
	// Without this it's possible for an attacker to mount a DNS rebinding attack
	// See https://github.com/99designs/aws-vault/issues/578
	if r.Host != ec2MetadataEndpointIP && r.Host != ec2MetadataEndpointAddr {
		http.Error(w, fmt.Sprintf("Access denied for host '%s'", r.Host), http.StatusUnauthorized)
		return
	}

	sc.next.ServeHTTP(w, r)
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
