package cli

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"

	"github.com/99designs/aws-vault/v7/server"
	"github.com/alecthomas/kingpin/v2"
)

func ConfigureProxyCommand(app *kingpin.Application) {
	stop := false
	isWsl := false
	serverAddress := ""
	cmd := app.Command("proxy", "Start a proxy for the ec2 instance role server locally.").
		Alias("server").
		Hidden()

	cmd.Flag("stop", "Stop the proxy").
		BoolVar(&stop)

	cmd.Flag("credentials-server-address", "Server address").
		Default(server.DefaultEc2CredentialsServerAddr).
		Hidden().
		StringVar(&serverAddress)

	//goland:noinspection GoBoolExpressions
	if runtime.GOOS == "linux" {
		cmd.Flag("wsl", "Proxy to credentials server running on Windows host").
			BoolVar(&isWsl)
	}

	cmd.Action(func(*kingpin.ParseContext) error {
		if stop {
			server.StopProxy()
			return nil
		}
		handleSigTerm()
		if (serverAddress == server.DefaultEc2CredentialsServerAddr) && isWsl {
			ip, err := getWslHost()
			if err != nil {
				return err
			}
			serverAddress = ip.String() + ":" + server.DefaultEc2CredentialsServerPort
		}
		return server.StartProxy(serverAddress)
	})
}

func getWslHost() (net.IP, error) {
	out, err := exec.Command("ip", "route").CombinedOutput()
	if err != nil {
		return net.IP{}, err
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "default") {
			return net.ParseIP(strings.Split(line, " ")[2]), nil
		}
	}
	return nil, fmt.Errorf("unable to find default gateway")
}

func handleSigTerm() {
	// shutdown
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		server.Shutdown()
		os.Exit(1)
	}()
}
