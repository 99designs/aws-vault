package cli

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/99designs/aws-vault/v6/server"
	"github.com/alecthomas/kingpin"
)

func ConfigureProxyCommand(app *kingpin.Application, a *AwsVault) {
	stop := false

	cmd := app.Command("proxy", "Start a proxy for the ec2 instance role server locally").
		Alias("server").
		Hidden()

	cmd.Flag("stop", "Stop the proxy").
		BoolVar(&stop)

	cmd.Action(func(*kingpin.ParseContext) error {
		if stop {
			server.StopProxy()
			return nil
		} else {
			handleSigTerm()
			return server.StartProxy()
		}
	})
}

func handleSigTerm() {
	// shutdown
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		server.Shutdown()
		os.Exit(1)
	}()
}
