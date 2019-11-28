// +build !darwin,!freebsd,!linux

package server

import (
	"errors"
	"log"
	"os"
	"os/exec"
	"time"
)

// StartCredentialProxy starts a `aws-vault server` process
func StartCredentialProxy() error {
	log.Println("Starting `aws-vault server` in the background")
	cmd := exec.Command(os.Args[0], "server")
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	time.Sleep(time.Second * 1)
	if !checkServerRunning(metadataBind) {
		return errors.New("The credential proxy server isn't running. Run aws-vault server as Administrator in the background and then try this command again")
	}
	return nil
}
