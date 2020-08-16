// +build linux

package server

import "os/exec"

func installEc2EndpointNetworkAlias() ([]byte, error) {
	return exec.Command("ip", "addr", "add", "169.254.169.254/24", "dev", "lo", "label", "lo:0").CombinedOutput()
}

func removeEc2EndpointNetworkAlias() ([]byte, error) {
	return exec.Command("ip", "addr", "del", "169.254.169.254/24", "dev", "lo", "label", "lo:0").CombinedOutput()
}
