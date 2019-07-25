// +build darwin freebsd

package server

import "os/exec"

func InstallNetworkAlias(ip string) ([]byte, error) {
	return exec.Command("ifconfig", "lo0", "alias", ip).CombinedOutput()
}
