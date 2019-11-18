// +build linux darwin

package cli

import (
	osexec "os/exec"
	"syscall"
)

func exec(command string, args []string, env []string) error {
	argv0, err := osexec.LookPath(command)
	if err != nil {
		return err
	}

	argv := make([]string, 0, 1+len(args))
	argv = append(argv, command)
	argv = append(argv, args...)

	return syscall.Exec(argv0, argv, env)
}
