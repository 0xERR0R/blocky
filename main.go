package main

import (
	"blocky/config"
	"blocky/server"
	"os"
	"os/signal"
	"syscall"

	prefixed "github.com/x-cray/logrus-prefixed-formatter"

	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
)

//nolint:gochecknoglobals
var version = "undefined"

//nolint:gochecknoglobals
var buildTime = "undefined"

func main() {
	cfg := config.NewConfig()
	configureLog(&cfg)

	printBanner()

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
