package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
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

	apiRequest := api.QueryRequest{
		Query: args[0],
		Type:  typeFlag,
	}
	jsonValue, err := json.Marshal(apiRequest)

	if err != nil {
		return fmt.Errorf("can't marshal request: %w", err)
	}

	resp, err := http.Post(apiURL(api.PathQueryPath), "application/json", bytes.NewBuffer(jsonValue))

	if err != nil {
		return fmt.Errorf("can't execute: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)

		return fmt.Errorf("response NOK, %s %s", resp.Status, string(body))
	}

	var result api.QueryResult
	err = json.NewDecoder(resp.Body).Decode(&result)

	if err != nil {
		return fmt.Errorf("can't read response: %w", err)
	}

	log.Log().Infof("Query result for '%s' (%s):", apiRequest.Query, apiRequest.Type)
	log.Log().Infof("\treason:        %20s", result.Reason)
	log.Log().Infof("\tresponse type: %20s", result.ResponseType)
	log.Log().Infof("\tresponse:      %20s", result.Response)
	log.Log().Infof("\treturn code:   %20s", result.ReturnCode)

	return nil
}
