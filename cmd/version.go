package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// NewVersionCommand creates new command instance
func NewVersionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Args:  cobra.NoArgs,
		Short: "Print the version number of blocky",
		Run:   printVersion,
	}
}

func printVersion(_ *cobra.Command, _ []string) {
	fmt.Println("blocky")
	fmt.Printf("Version: %s\n", version)
	fmt.Printf("Build time: %s\n", buildTime)
}
