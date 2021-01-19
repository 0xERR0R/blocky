package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

//nolint:gochecknoinits
func init() {
	rootCmd.AddCommand(NewVersionCommand())
}

func NewVersionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Args:  cobra.NoArgs,
		Short: "Print the version number of blocky",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("blocky")
			fmt.Printf("Version: %s\n", version)
			fmt.Printf("Build time: %s\n", buildTime)
		},
	}
}
