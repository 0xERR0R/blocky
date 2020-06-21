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

//nolint:gochecknoglobals
var rootCmd = &cobra.Command{
	Use:   "blocky",
	Short: "blocky is a DNS proxy ",
	Long: `A fast and configurable DNS Proxy
and ad-blocker for local network.
		   
Complete documentation is available at https://github.com/0xERR0R/blocky`,
	Run: func(cmd *cobra.Command, args []string) {
		serveCmd.Run(cmd, args)
	},
}

func apiURL(path string) string {
	return fmt.Sprintf("http://%s:%d%s", apiHost, apiPort, path)
}

//nolint:gochecknoinits
func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVarP(&configPath, "config", "c", "./config.yml", "path to config file")
	rootCmd.PersistentFlags().StringVar(&apiHost, "apiHost", "localhost", "host of blocky (API)")
	rootCmd.PersistentFlags().Uint16Var(&apiPort, "apiPort", 0, "port of blocky (API)")
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
}

func initConfig() {
	cfg = config.NewConfig(configPath)
	configureLog(&cfg)

	if apiPort == 0 {
		apiPort = cfg.HTTPPort
	}
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
