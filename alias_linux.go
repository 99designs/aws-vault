// build: linux

package main

import "os/exec"

func installNetworkAlias() ([]byte, error) {
	return exec.Command("ifconfig", "lo:0", "169.254.169.254").CombinedOutput()
}
