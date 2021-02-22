package cmd

import (
	"blocky/config"
	"blocky/log"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

//nolint:gochecknoglobals
var (
	version    = "undefined"
	buildTime  = "undefined"
	configPath string
	cfg        config.Config
	apiHost    string
	apiPort    uint16
)

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
	c.PersistentFlags().StringVar(&apiHost, "apiHost", "localhost", "host of blocky (API)")
	c.PersistentFlags().Uint16Var(&apiPort, "apiPort", 0, "port of blocky (API)")

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
	cfg = config.NewConfig(configPath)
	log.NewLogger(cfg.LogLevel, cfg.LogFormat)

	if apiPort == 0 {
		apiPort = cfg.HTTPPort
	}
}

func Execute() {
	if err := NewRootCommand().Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
