package cmd

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/0xERR0R/blocky/api"
	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/log"
	"github.com/spf13/cobra"
)

//nolint:gochecknoglobals
var (
	configPath string
	apiHost    string
	apiPort    uint16
	dnsHost    = defaultIPAddress
	dnsPort    = uint16(defaultDNSPort)
)

const (
	defaultPort         = 4000
	defaultHost         = "localhost"
	defaultConfigPath   = "./config.yml"
	configFileEnvVar    = "BLOCKY_CONFIG_FILE"
	configFileEnvVarOld = "CONFIG_FILE"
)

// NewRootCommand creates a new root cli command instance
func NewRootCommand() *cobra.Command {
	c := &cobra.Command{
		Use:   "blocky",
		Short: "blocky is a DNS proxy ",
		Long: `A fast and configurable DNS Proxy
and ad-blocker for local network.

Complete documentation is available at https://github.com/0xERR0R/blocky`,
		PreRunE: initConfigPreRun,
		RunE: func(cmd *cobra.Command, args []string) error {
			return newServeCommand().RunE(cmd, args)
		},
		SilenceUsage: true,
	}

	c.PersistentFlags().StringVarP(&configPath, "config", "c", defaultConfigPath, "path to config file or folder")
	c.PersistentFlags().StringVar(&apiHost, "apiHost", defaultHost, "host of blocky (API). Default overridden by config and CLI.") //nolint:lll
	c.PersistentFlags().Uint16Var(&apiPort, "apiPort", defaultPort, "port of blocky (API). Default overridden by config and CLI.") //nolint:lll

	c.AddCommand(newRefreshCommand(),
		NewQueryCommand(),
		NewVersionCommand(),
		newServeCommand(),
		newBlockingCommand(),
		NewListsCommand(),
		NewHealthcheckCommand(),
		newCacheCommand(),
		NewStatsCommand(),
		NewValidateCommand())

	return c
}

func apiURL() string {
	return fmt.Sprintf("http://%s%s", net.JoinHostPort(apiHost, strconv.Itoa(int(apiPort))), "/api")
}

// newAPIClient creates a new API client with the configured URL
func newAPIClient() (*api.ClientWithResponses, error) {
	client, err := api.NewClientWithResponses(apiURL())
	if err != nil {
		return nil, fmt.Errorf("can't create client: %w", err)
	}

	return client, nil
}

func initConfigPreRun(cmd *cobra.Command, args []string) error {
	return initConfig()
}

func initConfig() error {
	if configPath == defaultConfigPath {
		val, present := os.LookupEnv(configFileEnvVar)
		if present {
			configPath = val
		} else {
			val, present = os.LookupEnv(configFileEnvVarOld)
			if present {
				configPath = val
			}
		}
	}

	cfg, err := config.LoadConfig(configPath, false)
	if err != nil {
		return fmt.Errorf("unable to load configuration file '%s': %w", configPath, err)
	}

	log.Configure(&cfg.Log)

	if len(cfg.Ports.HTTP) != 0 {
		split := strings.Split(cfg.Ports.HTTP[0], ":")

		lastIdx := len(split) - 1

		apiHost = strings.Join(split[:lastIdx], ":")

		port, err := config.ConvertPort(split[lastIdx])
		if err != nil {
			return fmt.Errorf("can't convert port '%s' to number (1 - 65535): %w", split[lastIdx], err)
		}

		apiPort = port
	}

	if len(cfg.Ports.DNS) != 0 {
		host, port, err := splitListenAddress(cfg.Ports.DNS[0])
		if err != nil {
			return fmt.Errorf("can't parse DNS listen address '%s': %w", cfg.Ports.DNS[0], err)
		}

		if host != "" {
			if ip := net.ParseIP(host); ip == nil || !ip.IsUnspecified() {
				dnsHost = host
			}
		}

		dnsPort = port
	}

	return nil
}

// splitListenAddress splits a `ports.*` entry into host and port. Entries are normalized
// to ":port" when no host is given, so an empty host means "all interfaces".
func splitListenAddress(addr string) (host string, port uint16, err error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		// Not a host:port pair - treat the whole value as a port.
		host, portStr = "", addr
	}

	port, err = config.ConvertPort(portStr)
	if err != nil {
		return "", 0, fmt.Errorf("can't convert port '%s' to number (1 - 65535): %w", portStr, err)
	}

	return host, port, nil
}

// Execute starts the command
func Execute() {
	if err := NewRootCommand().Execute(); err != nil {
		os.Exit(1)
	}
}

type codeWithStatus interface {
	StatusCode() int
	Status() string
}

func printOkOrError(resp codeWithStatus, body string) error {
	if resp.StatusCode() == http.StatusOK {
		log.Log().Info("OK")
	} else {
		return fmt.Errorf("response NOK, %s %s", resp.Status(), body)
	}

	return nil
}
