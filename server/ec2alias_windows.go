//go:build windows
// +build windows

package server

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
)

var alreadyRegisteredLocalised = []string{
	"The object already exists",
	"Das Objekt ist bereits vorhanden",
	"El objeto ya existe",
}

var runAsAdministratorLocalised = []string{
	"Run as administrator",
	// truncate before 'Umlaut' to avoid encoding problems coming from Windows cmd
	"Als Administrator ausf",
	"Ejecutar como administrador",
}

func msgFound(localised []string, toTest string) bool {
	for _, value := range localised {
		if strings.Contains(toTest, value) {
			return true
		}
	}

	return false
}

func runAndWrapAdminErrors(name string, arg ...string) ([]byte, error) {
	out, err := exec.Command(name, arg...).CombinedOutput()
	if msgFound(runAsAdministratorLocalised, string(out)) {
		err = fmt.Errorf("Creation of network alias for server mode requires elevated permissions, run as administrator", err)
	}

	return out, err
}

func GetWslAddressAndNetwork() (net.IP, *net.IPNet, error) {
	out, err := runAndWrapAdminErrors("netsh", "interface", "ipv4", "show", "addresses", "vEthernet (WSL)")
	if err != nil {
		return net.IP{}, nil, err
	}
	ip := net.IP{}
	nt := &net.IPNet{}

	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		if strings.Contains(line, "IP Address:") {
			sip := strings.Trim(strings.Split(line, ":")[1], " \n\r\t")
			if ip = net.ParseIP(sip); ip == nil {
				return net.IP{}, nil, fmt.Errorf("Unable to parse IP address from WSL interface: %s", sip)
			}
		}
		if strings.Contains(line, "Subnet Prefix:") {
			snt := strings.Split(strings.Trim(strings.Split(line, ":")[1], " \n\r\t"), " ")[0]
			if _, nt, err = net.ParseCIDR(snt); err != nil {
				return net.IP{}, nil, fmt.Errorf("Unable to parse network from WSL interface: %s, %v", snt, err)
			}
		}
	}
	if (ip == nil) || (nt == nil) {
		return net.IP{}, nil, fmt.Errorf("Unable to find IP address and network from WSL interface")
	}
	return ip, nt, nil
}

func installEc2EndpointNetworkAlias() ([]byte, error) {
	out, err := runAndWrapAdminErrors("netsh", "interface", "ipv4", "add", "address", "Loopback Pseudo-Interface 1", "169.254.169.254", "255.255.0.0")
	if msgFound(alreadyRegisteredLocalised, string(out)) {
		return []byte{}, nil
	}

	return out, err
}

func removeEc2EndpointNetworkAlias() ([]byte, error) {
	return runAndWrapAdminErrors("netsh", "interface", "ipv4", "delete", "address", "Loopback Pseudo-Interface 1", "169.254.169.254", "255.255.0.0")
}
