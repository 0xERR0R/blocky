package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/evt"
	"github.com/0xERR0R/blocky/log"
	"github.com/0xERR0R/blocky/server"
	"github.com/0xERR0R/blocky/util"

	"github.com/spf13/cobra"
)

//nolint:gochecknoglobals
var (
	done              = make(chan bool, 1)
	isConfigMandatory = true
	signals           = make(chan os.Signal, 1)

	// raiseNetBindService is a seam so tests can stub the capability raise.
	raiseNetBindService = util.RaiseNetBindService
)

const shutdownTimeout = 10 * time.Second

func newServeCommand() *cobra.Command {
	return &cobra.Command{
		Use:               "serve",
		Args:              cobra.NoArgs,
		Short:             "start blocky DNS server (default command)",
		RunE:              startServer,
		PersistentPreRunE: initConfigPreRun,
		SilenceUsage:      true,
	}
}

// privilegedPortCapHint describes how to satisfy the CAP_NET_BIND_SERVICE
// requirement for binding ports below 1024.
const privilegedPortCapHint = "grant CAP_NET_BIND_SERVICE (Kubernetes " +
	"securityContext capabilities.add, or docker run --cap-add NET_BIND_SERVICE) " +
	"or use a port >= 1024"

// warnMissingPrivilegedPortCapability raises CAP_NET_BIND_SERVICE if it is
// available, and warns when a privileged port (< 1024) is configured but the
// capability could not be obtained. It never fails: any real bind error
// surfaces later from server.NewServer.
func warnMissingPrivilegedPortCapability(ports config.Ports) {
	effective, err := raiseNetBindService()
	if err != nil {
		if privileged := ports.PrivilegedPorts(); len(privileged) > 0 {
			log.Log().Warnf("could not adjust process capabilities (%v); binding "+
				"privileged port(s) %s may fail — %s",
				err, strings.Join(privileged, ", "), privilegedPortCapHint)

			return
		}

		log.Log().Warnf("could not adjust process capabilities: %v", err)

		return
	}

	if effective {
		return
	}

	if privileged := ports.PrivilegedPorts(); len(privileged) > 0 {
		log.Log().Warnf("configured to listen on privileged port(s) %s without "+
			"CAP_NET_BIND_SERVICE; %s", strings.Join(privileged, ", "), privilegedPortCapHint)
	}
}

func startServer(_ *cobra.Command, _ []string) error {
	printBanner()

	cfg, err := config.LoadConfig(configPath, isConfigMandatory)
	if err != nil {
		return fmt.Errorf("unable to load configuration: %w", err)
	}

	log.Configure(&cfg.Log)

	warnMissingPrivilegedPortCapability(cfg.Ports)

	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

	ctx, cancelFn := context.WithCancel(context.Background())
	defer cancelFn()

	srv, err := server.NewServer(ctx, cfg)
	if err != nil {
		return fmt.Errorf("can't start server: %w", err)
	}

	const errChanSize = 10
	errChan := make(chan error, errChanSize)

	srv.Start(ctx, errChan)

	var terminationErr error

	go func() {
		select {
		case <-signals:
			log.Log().Infof("Terminating...")

			// Cancel background operations (periodic refresh, etc.)
			cancelFn()

			// Create timeout context for graceful shutdown
			stopCtx, stopCancel := context.WithTimeout(context.Background(), shutdownTimeout)
			defer stopCancel()

			util.LogOnError(stopCtx, "can't stop server: ", srv.Stop(stopCtx))
			done <- true

		case err := <-errChan:
			log.Log().Error("server start failed: ", err)
			terminationErr = err
			done <- true
		}
	}()

	evt.LegacyBus().Publish(evt.ApplicationStarted, util.Version, util.BuildTime)
	<-done

	return terminationErr
}

func printBanner() {
	log.Log().Info("_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/")
	log.Log().Info("_/                                                              _/")
	log.Log().Info("_/                                                              _/")
	log.Log().Info("_/       _/        _/                      _/                   _/")
	log.Log().Info("_/      _/_/_/    _/    _/_/      _/_/_/  _/  _/    _/    _/    _/")
	log.Log().Info("_/     _/    _/  _/  _/    _/  _/        _/_/      _/    _/     _/")
	log.Log().Info("_/    _/    _/  _/  _/    _/  _/        _/  _/    _/    _/      _/")
	log.Log().Info("_/   _/_/_/    _/    _/_/      _/_/_/  _/    _/    _/_/_/       _/")
	log.Log().Info("_/                                                    _/        _/")
	log.Log().Info("_/                                               _/_/           _/")
	log.Log().Info("_/                                                              _/")
	log.Log().Info("_/                                                              _/")
	log.Log().Infof("_/  Version: %-18s Build time: %-18s  _/", util.Version, util.BuildTime)
	log.Log().Info("_/                                                              _/")
	log.Log().Info("_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/")
}
