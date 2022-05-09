package cmd

import (
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/0xERR0R/blocky/api"
	"github.com/0xERR0R/blocky/log"

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
	resp, err := http.Post(apiURL(api.PathListsRefresh), "application/json", nil)
	if err != nil {
		return fmt.Errorf("can't execute %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)

		return fmt.Errorf("response NOK, %s %s", resp.Status, string(body))
	}

	log.Log().Info("OK")

	return nil
}
