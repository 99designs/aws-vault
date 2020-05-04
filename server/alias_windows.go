// +build windows

package server

import (
	"fmt"
	"os/exec"
	"strings"
)

func installNetworkAlias() ([]byte, error) {
	out, err := exec.Command("netsh", "interface", "ipv4", "add", "address", "Loopback Pseudo-Interface 1", "169.254.169.254", "255.255.0.0").CombinedOutput()

	if err == nil || strings.Contains(string(out), "The object already exists") {
		return []byte{}, nil
	}

	if strings.Contains(string(out), "Run as administrator") {
		fmt.Println("Creation of network alias for server mode requires elevated permissions (Run as administrator).")
	}

	return out, err
}
