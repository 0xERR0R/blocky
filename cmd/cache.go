package cmd

import (
	"context"
	"fmt"

	"github.com/0xERR0R/blocky/api"
	"github.com/spf13/cobra"
)

func newCacheCommand() *cobra.Command {
	c := &cobra.Command{
		Use:               "cache",
		Short:             "Performs cache operations",
		PersistentPreRunE: initConfigPreRun,
	}
	c.AddCommand(&cobra.Command{
		Use:     "flush",
		Args:    cobra.NoArgs,
		Aliases: []string{"clear"},
		Short:   "Flush cache",
		RunE:    flushCache,
	})

	return c
}

func flushCache(_ *cobra.Command, _ []string) error {
	client, err := api.NewClientWithResponses(apiURL())
	if err != nil {
		return fmt.Errorf("can't create client: %w", err)
	}

	resp, err := client.CacheFlushWithResponse(context.Background())
	if err != nil {
		return fmt.Errorf("can't execute %w", err)
	}

	return printOkOrError(resp, string(resp.Body))
}
