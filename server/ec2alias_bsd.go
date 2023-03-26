//go:build darwin || freebsd || openbsd
// +build darwin freebsd openbsd

package server

import "os/exec"

func GetWslAddressAndNetwork() (net.IP, *net.IPNet, error) {
	return net.IP{}, net.IPNet{}, fmt.Errorf("WSL is a Windows only feature")
}

func installEc2EndpointNetworkAlias() ([]byte, error) {
	return exec.Command("ifconfig", "lo0", "alias", "169.254.169.254").CombinedOutput()
}

func removeEc2EndpointNetworkAlias() ([]byte, error) {
	return exec.Command("ifconfig", "lo0", "-alias", "169.254.169.254").CombinedOutput()
}
