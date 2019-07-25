// +build linux

package server

import (
	"fmt"
	"os/exec"
)

func InstallNetworkAlias(ip string) ([]byte, error) {
	return exec.Command("ip", "addr", "add", fmt.Sprintf("%s/24", ip), "dev", "lo", "label", "lo:0").CombinedOutput()
}
