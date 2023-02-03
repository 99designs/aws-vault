package vault

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
)

func executeProcess(process string) (string, error) {
	var cmdArgs []string
	if runtime.GOOS == "windows" {
		cmdArgs = []string{"cmd.exe", "/C", process}
	} else {
		cmdArgs = []string{"/bin/sh", "-c", process}
	}

	cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	cmd.Env = os.Environ()
	cmd.Stdin = os.Stdin
	cmd.Stderr = os.Stderr

	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("running command %q: %v", process, err)
	}
	return string(output), nil
}
