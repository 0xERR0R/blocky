package cmd

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

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
)

func newServeCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "serve",
		Args:  cobra.NoArgs,
		Short: "start blocky DNS server (default command)",
		RunE:  startServer,
	}
}

func startServer(_ *cobra.Command, _ []string) error {
	printBanner()

	cfg, err := config.LoadConfig(configPath, isConfigMandatory)
	if err != nil {
		return fmt.Errorf("unable to load configuration: %w", err)
	}

	log.ConfigureLogger(cfg.LogLevel, cfg.LogFormat, cfg.LogTimestamp)

	signals := make(chan os.Signal, 1)

	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

	srv, err := server.NewServer(cfg)
	if err != nil {
		return fmt.Errorf("can't start server: %w", err)
	}

	const errChanSize = 10
	errChan := make(chan error, errChanSize)

	srv.Start(errChan)

	go func() {
		select {
		case <-signals:
			log.Log().Infof("Terminating...")
			util.LogOnError("can't stop server: ", srv.Stop())
			done <- true

		case err := <-errChan:
			log.Log().Error("server start failed: ", err)
			done <- true
		}
	}()

	evt.Bus().Publish(evt.ApplicationStarted, util.Version, util.BuildTime)
	<-done

	return nil
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
