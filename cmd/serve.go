package cmd

import (
	"net/http"
	"os"
	"os/signal"
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
	done chan bool
)

func newServeCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "serve",
		Args:  cobra.NoArgs,
		Short: "start blocky DNS server (default command)",
		Run:   startServer,
	}
}

func startServer(_ *cobra.Command, _ []string) {
	printBanner()

	config.LoadConfig(configPath, true)
	log.ConfigureLogger(config.GetConfig().LogLevel, config.GetConfig().LogFormat, config.GetConfig().LogTimestamp)

	configureHTTPClient(config.GetConfig())

	signals := make(chan os.Signal, 1)
	done = make(chan bool, 1)

	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

	srv, err := server.NewServer(config.GetConfig())
	util.FatalOnError("cant start server: ", err)

	srv.Start()

	go func() {
		<-signals
		log.Log().Infof("Terminating...")
		srv.Stop()
		done <- true
	}()

	evt.Bus().Publish(evt.ApplicationStarted, util.Version, util.BuildTime)
	<-done
}

func configureHTTPClient(cfg *config.Config) {
	http.DefaultTransport = &http.Transport{
		Dial:                (util.Dialer(cfg)).Dial,
		TLSHandshakeTimeout: 5 * time.Second,
	}
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
