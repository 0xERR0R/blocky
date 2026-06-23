package cmd

import (
	"errors"
	"log/slog"
	"os"

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
	slog.Info("Validating configuration file: " + configPath)

	_, err := os.Stat(configPath)
	if err != nil && errors.Is(err, os.ErrNotExist) {
		return errors.New("configuration path does not exist")
	}

	err = initConfig()
	if err != nil {
		return err
	}

	slog.Info("Configuration is valid")

	return nil
}
