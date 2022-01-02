package cmd

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/log"
	"github.com/0xERR0R/blocky/util"

	"github.com/spf13/cobra"
)

//nolint:gochecknoglobals
var (
	configPath string
	apiHost    string
	apiPort    uint16
)

// NewRootCommand creates a new root cli command instance
func NewRootCommand() *cobra.Command {
	c := &cobra.Command{
		Use:   "blocky",
		Short: "blocky is a DNS proxy ",
		Long: `A fast and configurable DNS Proxy
and ad-blocker for local network.

Complete documentation is available at https://github.com/0xERR0R/blocky`,
		Run: func(cmd *cobra.Command, args []string) {
			newServeCommand().Run(cmd, args)
		},
	}

	c.PersistentFlags().StringVarP(&configPath, "config", "c", "./config.yml", "path to config file")
	c.PersistentFlags().StringVar(&apiHost, "apiHost", "localhost", "host of blocky (API). Default overridden by config and CLI.") // nolint:lll
	c.PersistentFlags().Uint16Var(&apiPort, "apiPort", 4000, "port of blocky (API). Default overridden by config and CLI.")

	c.AddCommand(newRefreshCommand(),
		NewQueryCommand(),
		NewVersionCommand(),
		newServeCommand(),
		newBlockingCommand(),
		NewListsCommand())

	return c
}

func apiURL(path string) string {
	return fmt.Sprintf("http://%s:%d%s", apiHost, apiPort, path)
}

//nolint:gochecknoinits
func init() {
	cobra.OnInitialize(initConfig)
}

func initConfig() {
	config.LoadConfig(configPath, false)
	log.ConfigureLogger(config.GetConfig().LogLevel, config.GetConfig().LogFormat, config.GetConfig().LogTimestamp)

	if len(config.GetConfig().HTTPPorts) != 0 {
		split := strings.Split(config.GetConfig().HTTPPorts[0], ":")

		lastIdx := len(split) - 1

		apiHost = strings.Join(split[:lastIdx], ":")

		var p uint64
		p, err := strconv.ParseUint(strings.TrimSpace(split[lastIdx]), 10, 16)

		if err != nil {
			util.FatalOnError("can't convert port to number (1 - 65535)", err)
			return
		}

		apiPort = uint16(p)
	}
}

// Execute starts the command
func Execute() {
	if err := NewRootCommand().Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
