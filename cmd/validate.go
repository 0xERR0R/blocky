package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/log"
	"github.com/sirupsen/logrus"

	"github.com/spf13/cobra"
)

const validateCmdName = "validate"

// NewValidateCommand creates new command instance
func NewValidateCommand() *cobra.Command {
	return &cobra.Command{
		Use:   validateCmdName,
		Args:  cobra.NoArgs,
		Short: "Validates the configuration",
		RunE:  validateConfiguration,
	}
}

func validateConfiguration(_ *cobra.Command, _ []string) error {
	log.Log().Infof("Validating configuration file: %s", configPath)

	_, err := os.Stat(configPath)
	if err != nil && errors.Is(err, os.ErrNotExist) {
		return errors.New("configuration path does not exist")
	}

	_, err = loadConfig(false, func(cfg *config.Config) {
		logCfg := commandLogConfig(cfg)

		// validate reports what loading the config logs, so log.level must not hide it
		logCfg.Level = max(logCfg.Level, logrus.InfoLevel)

		log.Configure(&logCfg)
	})
	if err != nil {
		return fmt.Errorf("unable to load configuration file '%s': %w", configPath, err)
	}

	log.Log().Info("Configuration is valid")

	return nil
}
