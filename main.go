package main

import (
	"blocky/config"
	"blocky/server"
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	prefixed "github.com/x-cray/logrus-prefixed-formatter"

	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
)

//nolint:gochecknoglobals
var version = "undefined"

//nolint:gochecknoglobals
var buildTime = "undefined"

func main() {
	configPath := flag.String("config", "./config.yml", "Path to config file.")
	flag.Parse()

	cfg := config.NewConfig(*configPath)
	configureLog(&cfg)

	printBanner()

	configureHTTPClient(&cfg)

	signals := make(chan os.Signal)
	done := make(chan bool)

	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

	server, err := server.NewServer(&cfg)
	if err != nil {
		log.Fatal("cant start server ", err)
	}

	server.Start()

	go func() {
		<-signals
		log.Infof("Terminating...")
		server.Stop()
		done <- true
	}()

	<-done
}

func configureHTTPClient(cfg *config.Config) {
	if cfg.BootstrapDNS != (config.Upstream{}) {
		if cfg.BootstrapDNS.Net == "tcp" || cfg.BootstrapDNS.Net == "udp" {
			dns := net.JoinHostPort(cfg.BootstrapDNS.Host, fmt.Sprint(cfg.BootstrapDNS.Port))
			log.Debugf("using %s as bootstrap dns server", dns)

			r := &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
					d := net.Dialer{
						Timeout: time.Millisecond * time.Duration(2000),
					}
					return d.DialContext(ctx, cfg.BootstrapDNS.Net, dns)
				}}

			http.DefaultTransport = &http.Transport{
				Dial: (&net.Dialer{
					Timeout:  5 * time.Second,
					Resolver: r,
				}).Dial,
				TLSHandshakeTimeout: 5 * time.Second,
			}
		} else {
			log.Fatal("bootstrap dns net should be udp or tcs")
		}
	}
}

func configureLog(cfg *config.Config) {
	if level, err := log.ParseLevel(cfg.LogLevel); err != nil {
		log.Fatalf("invalid log level %s %v", cfg.LogLevel, err)
	} else {
		log.SetLevel(level)
	}

	logFormatter := &prefixed.TextFormatter{
		TimestampFormat:  "2006-01-02 15:04:05",
		FullTimestamp:    true,
		ForceFormatting:  true,
		ForceColors:      true,
		QuoteEmptyFields: true}

	logFormatter.SetColorScheme(&prefixed.ColorScheme{
		PrefixStyle:    "blue+b",
		TimestampStyle: "white+h",
	})

	logrus.SetFormatter(logFormatter)
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
