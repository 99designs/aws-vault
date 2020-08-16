// +build windows

package server

import (
	"fmt"
	"os/exec"
	"strings"
)

var alreadyRegisteredLocalised = []string{
	"The object already exists",
	"Das Objekt ist bereits vorhanden",
}

var runAsAdministratorLocalised = []string{
	"Run as administrator",
	// truncate before 'Umlaut' to avoid encoding problems coming from Windows cmd
	"Als Administrator ausf",
}

func installEc2EndpointNetworkAlias() ([]byte, error) {
	out, err := exec.Command("netsh", "interface", "ipv4", "add", "address", "Loopback Pseudo-Interface 1", "169.254.169.254", "255.255.0.0").CombinedOutput()

	outMsg := string(out)

	if err == nil || msgFound(alreadyRegisteredLocalised, outMsg) {
		return []byte{}, nil
	}

	if msgFound(runAsAdministratorLocalised, outMsg) {
		fmt.Println("Creation of network alias for server mode requires elevated permissions (Run as administrator).")
	}

	return out, err
}

func msgFound(localised []string, toTest string) bool {
	for _, value := range localised {
		if strings.Contains(toTest, value) {
			return true
		}
	}

	return false
}
