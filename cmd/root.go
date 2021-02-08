package cmd

import (
	"blocky/config"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	prefixed "github.com/x-cray/logrus-prefixed-formatter"

	log "github.com/sirupsen/logrus"
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

func configureLog(cfg *config.Config) {
	if level, err := log.ParseLevel(cfg.LogLevel); err != nil {
		log.Fatalf("invalid log level %s %v", cfg.LogLevel, err)
	} else {
		log.SetLevel(level)
	}

	if cfg.LogFormat == config.CfgLogFormatText {
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

		log.SetFormatter(logFormatter)
	}

	if cfg.LogFormat == config.CfgLogFormatJSON {
		log.SetFormatter(&log.JSONFormatter{})
	}

	log.SetOutput(os.Stdout)
}

func initConfig() {
	cfg = config.NewConfig(configPath)
	configureLog(&cfg)

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
