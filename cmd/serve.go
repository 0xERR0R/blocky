package cmd

import (
	"blocky/config"
	"blocky/evt"
	"blocky/server"
	"blocky/util"
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"blocky/log"

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

	cfg = config.NewConfig(configPath, true)
	log.ConfigureLogger(cfg.LogLevel, cfg.LogFormat, cfg.LogTimestamp)

	configureHTTPClient(&cfg)

	signals := make(chan os.Signal)
	done = make(chan bool)

	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

	srv, err := server.NewServer(&cfg)
	util.FatalOnError("cant start server: ", err)

	srv.Start()

	go func() {
		<-signals
		log.Log().Infof("Terminating...")
		srv.Stop()
		done <- true
	}()

	evt.Bus().Publish(evt.ApplicationStarted, version, buildTime)
	<-done
}

func configureHTTPClient(cfg *config.Config) {
	if cfg.BootstrapDNS != (config.Upstream{}) {
		if cfg.BootstrapDNS.Net == config.NetTCPUDP {
			dns := net.JoinHostPort(cfg.BootstrapDNS.Host, fmt.Sprint(cfg.BootstrapDNS.Port))
			log.Log().Debugf("using %s as bootstrap dns server", dns)

			r := &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
					d := net.Dialer{
						Timeout: time.Millisecond * time.Duration(2000),
					}
					return d.DialContext(ctx, "udp", dns)
				}}

			http.DefaultTransport = &http.Transport{
				Dial: (&net.Dialer{
					Timeout:  5 * time.Second,
					Resolver: r,
				}).Dial,
				TLSHandshakeTimeout: 5 * time.Second,
			}
		} else {
			log.Log().Fatal("bootstrap dns net should be tcp+udp")
		}
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
	log.Log().Infof("_/  Version: %-18s Build time: %-18s  _/", version, buildTime)
	log.Log().Info("_/                                                              _/")
	log.Log().Info("_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/")
}
