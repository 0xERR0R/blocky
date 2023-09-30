package cmd

import (
	"context"
	"fmt"

	"github.com/0xERR0R/blocky/api"
	"github.com/spf13/cobra"
)

// NewListsCommand creates new command instance
func NewListsCommand() *cobra.Command {
	c := &cobra.Command{
		Use:   "lists",
		Short: "lists operations",
	}

	c.AddCommand(newRefreshCommand())

	return c
}

func newRefreshCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "refresh",
		Short: "refreshes all lists",
		RunE:  refreshList,
	}
}

func refreshList(_ *cobra.Command, _ []string) error {
	client, err := api.NewClientWithResponses(apiURL())
	if err != nil {
		return fmt.Errorf("can't create client: %w", err)
	}

	resp, err := client.ListRefreshWithResponse(context.Background())
	if err != nil {
		return fmt.Errorf("can't execute %w", err)
	}

	return printOkOrError(resp, string(resp.Body))
}
