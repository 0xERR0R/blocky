package cmd

import (
	"fmt"

	"github.com/0xERR0R/blocky/util"
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
	fmt.Printf("Version: %s\n", util.Version)
	fmt.Printf("Build time: %s\n", util.BuildTime)
	fmt.Printf("Architecture: %s\n", util.Architecture)
}
