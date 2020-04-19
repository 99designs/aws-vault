// +build darwin freebsd linux

package server

import (
	"log"
	"os"
	"os/exec"
)

// StartEc2EndpointProxyServerProcess starts a `aws-vault server` process
func StartEc2EndpointProxyServerProcess() error {
	log.Println("Starting `aws-vault server` as root in the background")
	cmd := exec.Command("sudo", "-b", os.Args[0], "server")
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
