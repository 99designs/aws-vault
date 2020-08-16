// +build windows

package server

import (
	"errors"
	"log"
	"os"
	"os/exec"
	"time"
)

// StartEc2EndpointProxyServerProcess starts a `aws-vault server` process
func StartEc2EndpointProxyServerProcess() error {
	log.Println("Starting `aws-vault server` in the background")
	cmd := exec.Command(os.Args[0], "server")
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	time.Sleep(time.Second * 1)
	if !isServerRunning(ec2MetadataEndpointAddr) {
		return errors.New("The EC2 Instance Metadata endpoint proxy server isn't running. Run `aws-vault server` as Administrator or root in the background and then try this command again")
	}
	return nil
}

func KillEc2EndpointProxyServerProcess() error {
	log.Println("Killing `aws-vault server` process")
	return exec.Command("taskkill", "/f", "/im" "aws-vault server", "/t").Run()
}
