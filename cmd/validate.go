package cmd

import (
	"errors"
	"os"

	"github.com/0xERR0R/blocky/log"

	"github.com/spf13/cobra"
)

// NewValidateCommand creates new command instance
func NewValidateCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "validate",
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

	err = initConfig()
	if err != nil {
		return err
	}

	log.Log().Info("Configuration is valid")

	return nil
}
