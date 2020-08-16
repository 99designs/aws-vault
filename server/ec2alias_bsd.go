// +build darwin freebsd

package server

import "os/exec"

func installEc2EndpointNetworkAlias() ([]byte, error) {
	return exec.Command("ifconfig", "lo0", "alias", "169.254.169.254").CombinedOutput()
}

func removeEc2EndpointNetworkAlias() ([]byte, error) {
	return exec.Command("ifconfig", "lo0", "-alias", "169.254.169.254").CombinedOutput()
}
