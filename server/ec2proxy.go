package server

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

const (
	ec2MetadataEndpointIP   = "169.254.169.254"
	ec2MetadataEndpointAddr = "169.254.169.254:80"
)

// startProxy starts a http proxy server that listens on the standard EC2 Instance Metadata endpoint http://169.254.169.254:80/
// and forwards requests through to the running `aws-vault exec` command
func startProxy(ctx context.Context) error {
	var localServerURL, err = url.Parse(fmt.Sprintf("http://%s/", ec2CredentialsServerAddr))
	if err != nil {
		return err
	}

	defer func() {
		// always try to clean up
		_, err := removeEc2EndpointNetworkAlias()
		if err != nil {
			log.Printf("Error removing network alias: %+v", err)
		}
	}()

	if output, err := installEc2EndpointNetworkAlias(); err != nil {
		return fmt.Errorf("installing network alias: %s: %w", strings.TrimSpace(string(output)), err)
	}

	l, err := net.Listen("tcp", ec2MetadataEndpointAddr)
	if err != nil {
		return err
	}

	handler := http.NewServeMux()
	handler.Handle("/", httputil.NewSingleHostReverseProxy(localServerURL))
	srv := &http.Server{Handler: handler}

	log.Printf("EC2 Instance Metadata endpoint proxy server running on %s", l.Addr())

	go func() {
		err := srv.Serve(l)
		if err != nil && err != http.ErrServerClosed {
			log.Printf("Ungraceful termination of server: %+v", err)
		}
	}()

	<-ctx.Done()

	return srv.Shutdown(context.TODO())
}
