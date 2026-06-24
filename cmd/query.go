package cmd

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/0xERR0R/blocky/api"
	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

// NewQueryCommand creates new command instance
func NewQueryCommand() *cobra.Command {
	c := &cobra.Command{
		Use:               "query <domain>",
		Args:              cobra.ExactArgs(1),
		Short:             "performs DNS query",
		RunE:              query,
		PersistentPreRunE: initConfigPreRun,
	}

	c.Flags().StringP("type", "t", "A", "query type (A, AAAA, ...)")

	return c
}

func query(cmd *cobra.Command, args []string) error {
	typeFlag, _ := cmd.Flags().GetString("type")
	qType := dns.StringToType[typeFlag]

	if qType == dns.TypeNone {
		return fmt.Errorf("unknown query type '%s'", typeFlag)
	}

	client, err := newAPIClient()
	if err != nil {
		return err
	}

	req := api.ApiQueryRequest{
		Query: args[0],
		Type:  typeFlag,
	}

	resp, err := client.QueryWithResponse(cmd.Context(), req)
	if err != nil {
		return fmt.Errorf("can't execute %w", err)
	}

	if resp.StatusCode() != http.StatusOK {
		return fmt.Errorf("response NOK, %s %s", resp.Status(), string(resp.Body))
	}

	slog.Info(fmt.Sprintf("Query result for '%s' (%s):", req.Query, req.Type))
	slog.Info(fmt.Sprintf("\treason:        %20s", resp.JSON200.Reason))
	slog.Info(fmt.Sprintf("\tresponse type: %20s", resp.JSON200.ResponseType))
	slog.Info(fmt.Sprintf("\tresponse:      %20s", resp.JSON200.Response))
	slog.Info(fmt.Sprintf("\treturn code:   %20s", resp.JSON200.ReturnCode))

	return nil
}
