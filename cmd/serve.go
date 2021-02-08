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

	log "github.com/sirupsen/logrus"
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

	configureHTTPClient(&cfg)

	signals := make(chan os.Signal)
	done = make(chan bool)

	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

	srv, err := server.NewServer(&cfg)
	util.FatalOnError("cant start server: ", err)

	srv.Start()

	go func() {
		<-signals
		log.Infof("Terminating...")
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
			log.Debugf("using %s as bootstrap dns server", dns)

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
			log.Fatal("bootstrap dns net should be tcp+udp")
		}
	}
}

func printBanner() {
	log.Info("_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/")
	log.Info("_/                                                              _/")
	log.Info("_/                                                              _/")
	log.Info("_/       _/        _/                      _/                   _/")
	log.Info("_/      _/_/_/    _/    _/_/      _/_/_/  _/  _/    _/    _/    _/")
	log.Info("_/     _/    _/  _/  _/    _/  _/        _/_/      _/    _/     _/")
	log.Info("_/    _/    _/  _/  _/    _/  _/        _/  _/    _/    _/      _/")
	log.Info("_/   _/_/_/    _/    _/_/      _/_/_/  _/    _/    _/_/_/       _/")
	log.Info("_/                                                    _/        _/")
	log.Info("_/                                               _/_/           _/")
	log.Info("_/                                                              _/")
	log.Info("_/                                                              _/")
	log.Infof("_/  Version: %-18s Build time: %-18s  _/", version, buildTime)
	log.Info("_/                                                              _/")
	log.Info("_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/")
}
