package cmd

import (
	"context"
	"fmt"
	"net/http"

	"github.com/0xERR0R/blocky/api"
	"github.com/0xERR0R/blocky/log"
	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

// NewQueryCommand creates new command instance
func NewQueryCommand() *cobra.Command {
	c := &cobra.Command{
		Use:   "query <domain>",
		Args:  cobra.ExactArgs(1),
		Short: "performs DNS query",
		RunE:  query,
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

	client, err := api.NewClientWithResponses(apiURL())
	if err != nil {
		return fmt.Errorf("can't create client: %w", err)
	}

	req := api.ApiQueryRequest{
		Query: args[0],
		Type:  typeFlag,
	}

	resp, err := client.QueryWithResponse(context.Background(), req)
	if err != nil {
		return fmt.Errorf("can't execute %w", err)
	}

	if resp.StatusCode() != http.StatusOK {
		return fmt.Errorf("response NOK, %s %s", resp.Status(), string(resp.Body))
	}

	log.Log().Infof("Query result for '%s' (%s):", req.Query, req.Type)
	log.Log().Infof("\treason:        %20s", resp.JSON200.Reason)
	log.Log().Infof("\tresponse type: %20s", resp.JSON200.ResponseType)
	log.Log().Infof("\tresponse:      %20s", resp.JSON200.Response)
	log.Log().Infof("\treturn code:   %20s", resp.JSON200.ReturnCode)

	return nil
}
