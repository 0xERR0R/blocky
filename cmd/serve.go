// Modified by Chris Snell, 2026
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/configstore"
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

func startServer(_ *cobra.Command, _ []string) error {
	// If GOMEMLIMIT env var isn't set, default to 90% of any cgroup memory
	// limit. Without this, Go's GC doesn't know about container limits and
	// allows RSS to grow past the cgroup boundary, causing OOM kills.
	if os.Getenv("GOMEMLIMIT") == "" {
		if limit := readCgroupMemoryLimit(); limit > 0 {
			softLimit := limit * 9 / 10
			debug.SetMemoryLimit(softLimit)
		}
	}

	printBanner()

	cfg, err := config.LoadConfig(configPath, isConfigMandatory)
	if err != nil {
		return fmt.Errorf("unable to load configuration: %w", err)
	}

	log.Configure(&cfg.Log)

	// If databasePath is set, open ConfigStore and apply DB-backed config
	var store *configstore.ConfigStore

	if cfg.DatabasePath != "" {
		var storeErr error

		store, storeErr = configstore.Open(cfg.DatabasePath)
		if storeErr != nil {
			return fmt.Errorf("open config database: %w", storeErr)
		}

		defer store.Close()

		if err := store.SeedFromConfig(cfg); err != nil {
			return fmt.Errorf("seed config database: %w", err)
		}

		// DB replaces dynamic sections
		cfg.Blocking, err = store.BuildBlockingConfig(cfg.Blocking)
		if err != nil {
			return fmt.Errorf("build blocking config from DB: %w", err)
		}

		cfg.CustomDNS, err = store.BuildCustomDNSConfig(cfg.CustomDNS)
		if err != nil {
			return fmt.Errorf("build custom DNS config from DB: %w", err)
		}

		log.Log().Info("Using database-backed configuration from ", cfg.DatabasePath)
	}

	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

	ctx, cancelFn := context.WithCancel(context.Background())
	defer cancelFn()

	srv, err := server.NewServer(ctx, cfg, store)
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

	evt.Bus().Publish(evt.ApplicationStarted, util.Version, util.BuildTime)
	<-done

	return terminationErr
}

// readCgroupMemoryLimit reads the memory limit from cgroup v2 or v1.
// Returns 0 if not running in a cgroup or the limit is effectively unlimited.
func readCgroupMemoryLimit() int64 {
	// cgroup v2
	if data, err := os.ReadFile("/sys/fs/cgroup/memory.max"); err == nil {
		return parseCgroupLimit(string(data))
	}

	// cgroup v1
	if data, err := os.ReadFile("/sys/fs/cgroup/memory/memory.limit_in_bytes"); err == nil {
		return parseCgroupLimit(string(data))
	}

	return 0
}

func parseCgroupLimit(s string) int64 {
	s = strings.TrimSpace(s)
	if s == "" || s == "max" {
		return 0
	}

	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0
	}

	// cgroup v1 uses a very large number (page-aligned near max int64) for "unlimited"
	const unlimitedThreshold = 1 << 62
	if v >= unlimitedThreshold {
		return 0
	}

	return v
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
