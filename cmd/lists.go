package cmd

import (
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
		Run:   refreshList,
	}
}

func refreshList(_ *cobra.Command, _ []string) {
	resp, err := http.Post(apiURL(api.PathListsRefresh), "application/json", nil)
	if err != nil {
		log.Log().Fatal("can't execute", err)

		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		log.Log().Fatalf("NOK: %s %s", resp.Status, string(body))

		return
	}

	log.Log().Info("OK")
}
