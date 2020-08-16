// +build !darwin,!freebsd,!linux

package server

import (
	"errors"
	"log"
	"os"
	"os/exec"
	"time"
)

// StartEc2EndpointProxyServerProcess starts a `aws-vault proxy` process
func StartEc2EndpointProxyServerProcess() error {
	log.Println("Starting `aws-vault proxy`")
	cmd := exec.Command(awsVaultExecutable(), "proxy")
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	time.Sleep(time.Second * 1)
	if !isProxyRunning() {
		return errors.New("The EC2 Instance Metadata endpoint proxy server isn't running. Run `aws-vault proxy` as Administrator or root in the background and then try this command again")
	}
	return nil
}
