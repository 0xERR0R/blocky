// Modified by Chris Snell, 2026
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"errors"
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
	"github.com/0xERR0R/blocky/pkg/advertise"
	"github.com/0xERR0R/blocky/pkg/winservice"
	"github.com/0xERR0R/blocky/server"
	"github.com/0xERR0R/blocky/util"

	"github.com/spf13/cobra"
)

//nolint:gochecknoglobals
var (
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
	if winservice.IsService() {
		return winservice.Run(runServer)
	}

	return runInteractive()
}

// runServer is the core server lifecycle, controlled by the given context.
// When ctx is cancelled, the server shuts down gracefully.
func runServer(ctx context.Context) error {
	if os.Getenv("GOMEMLIMIT") == "" {
		if limit := readCgroupMemoryLimit(); limit > 0 {
			debug.SetMemoryLimit(limit * 9 / 10)
		}
	}

	printBanner()

	cfg, err := config.LoadConfig(configPath, isConfigMandatory)
	if err != nil {
		return fmt.Errorf("unable to load configuration: %w", err)
	}

	log.Configure(&cfg.Log)

	warnMissingPrivilegedPortCapability(cfg.Ports)

	var store *configstore.ConfigStore

	if cfg.DatabasePath != "" {
		var storeErr error

		store, storeErr = configstore.Open(cfg.DatabasePath)
		if storeErr != nil {
			return fmt.Errorf("open config database: %w", storeErr)
		}

		defer store.Close()

		cfg.Blocking, err = store.BuildBlockingConfig(cfg.Blocking)
		if err != nil {
			return fmt.Errorf("build blocking config from DB: %w", err)
		}

		cfg.CustomDNS, err = store.BuildCustomDNSConfig(cfg.CustomDNS)
		if err != nil {
			return fmt.Errorf("build custom DNS config from DB: %w", err)
		}

		cfg.Upstreams, err = store.BuildUpstreamsConfig(cfg.Upstreams)
		if err != nil {
			return fmt.Errorf("build upstreams config from DB: %w", err)
		}

		log.Log().Info("Using database-backed configuration from ", cfg.DatabasePath)
	} else {
		return errors.New("databasePath is required: upstream configuration now lives in SQLite, " +
			"set databasePath in your YAML config (see docs/migration-upstreams.md)")
	}

	if err := injectAdvertiseRecords(cfg); err != nil {
		return fmt.Errorf("advertise DNS records: %w", err)
	}

	serverCtx, cancelServer := context.WithCancel(ctx)
	defer cancelServer()

	srv, err := server.NewServer(serverCtx, cfg, store)
	if err != nil {
		return fmt.Errorf("can't start server: %w", err)
	}

	const errChanSize = 10
	errChan := make(chan error, errChanSize)

	srv.Start(serverCtx, errChan)

	evt.Bus().Publish(evt.ApplicationStarted, util.Version, util.BuildTime)

	// Wait for context cancellation (service stop / signal) or fatal error
	select {
	case <-ctx.Done():
		log.Log().Infof("Terminating...")

		stopCtx, stopCancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer stopCancel()

		util.LogOnError(stopCtx, "can't stop server: ", srv.Stop(stopCtx))

		return nil

	case err := <-errChan:
		log.Log().Error("server start failed: ", err)

		return err
	}
}

// runInteractive runs the server in interactive (non-service) mode,
// responding to OS signals for shutdown.
func runInteractive() error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-signals
		cancel()
	}()

	return runServer(ctx)
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

// injectAdvertiseRecords resolves the advertise address and injects DNS records
// for each configured client group endpoint domain into the CustomDNS mapping.
func injectAdvertiseRecords(cfg *config.Config) error {
	cge := cfg.ClientGroupEndpoints
	if cge.AdvertiseAddress == "" || len(cge.Domains) == 0 {
		return nil
	}

	ip, err := advertise.ResolveAddress(cge.AdvertiseAddress)
	if err != nil {
		return err
	}

	if ip == nil {
		return nil
	}

	if cfg.CustomDNS.Mapping == nil {
		cfg.CustomDNS.Mapping = make(config.CustomDNSMapping)
	}

	const advertiseTTL = 3600
	advertise.InjectRecords(cfg.CustomDNS.Mapping, cge.Domains, ip, advertiseTTL)

	return nil
}

func printBanner() {
	log.Log().Info("                             @@@@@@@@@@@@                                 ")
	log.Log().Info("                        @@@@@@@@@@@@@@@@@@@@@@@                           ")
	log.Log().Info("                      @@@@@**+===========+*%@@@@@@                        ")
	log.Log().Info("                    @@@%+=====================+#@@@@                      ")
	log.Log().Info("                  @@@@+==========================*@@@@                    ")
	log.Log().Info("                 @@@#==============================*@@@                   ")
	log.Log().Info("                @@@*=================================%@@@                 ")
	log.Log().Info("               @@@#*@@@@===========+%%%*==============*@@@                ")
	log.Log().Info("              @@@#*@@ :@%=========%@@%@@@==============*@@                ")
	log.Log().Info("             @@@*=%@@@@@%========#@@  #@@@==============%@@               ")
	log.Log().Info("           @@@%===%@@@@@=========@@@%+@@@@===============@@@              ")
	log.Log().Info("        @@@@#======%%%*==========%@@@@@@@@===============*@@              ")
	log.Log().Info("      @@@%========================@@@@@@@*================@@@             ")
	log.Log().Info("     @@@+==========================*%%%*==================*@@             ")
	log.Log().Info("    @@@====================================================@@             ")
	log.Log().Info("    @@=+%+=================================================@@@            ")
	log.Log().Info("   @@@=*@*=======*@@@======================================@@@            ")
	log.Log().Info("   @@#==*========@@@#================================*@====%@@            ")
	log.Log().Info("   @@%============================+%@================@%====#@@            ")
	log.Log().Info("   @@@==========================+@@@================@@=====*@@            ")
	log.Log().Info("    @@@=====================+#@@@@#================@@*=====*@@            ")
	log.Log().Info("     @@@%+=============*#%@@@#%@@*===============#@@*+=====#@@            ")
	log.Log().Info("      @@@@@@%%##%%@@@@@%**===@@#==============+#@@#*+======#@@            ")
	log.Log().Info("         @@@@@@@@@@@#=====*@@*==========+**%@@@@#**+=======%@@            ")
	log.Log().Info("            @@==%@@@***%@@#+=====+*#@@@@@@@%*=#@**+========@@@            ")
	log.Log().Info("            @@@+==*****+====+*%@@@@@@@@%------*%*==========@@@            ")
	log.Log().Info("             @@@@%#*+++**%@@@@@@     @@*------%*==========+@@             ")
	log.Log().Info("                @@@@@@@@@@@@         @@+----::@+==========*@@             ")
	log.Log().Info("                                     @@=-:::::@===========%@@             ")
	log.Log().Info("                                     @@::::::-@===========@@@             ")
	log.Log().Info("                                    @@#::::::*%==========+@@              ")
	log.Log().Info("                                    @@=::::::@*==========#@@              ")
	log.Log().Info("                                    @@:::::::@===========@@@              ")
	log.Log().Info("                                   @@%::::::=@===========@@@              ")
	log.Log().Info("                                   @@=::::::@%==========*@@               ")
	log.Log().Info("                                  @@@:::::::@*==========%@@               ")
	log.Log().Info("                                  @@@::::::=@===========@@@               ")
	log.Log().Info("                                  @@=::::::%@===========@@                ")
	log.Log().Info("                                 @@@:::::::@*==========*@@                ")
	log.Log().Infof("  Blockasaurus v%-20s Build: %s", util.Version, util.BuildTime)
}
