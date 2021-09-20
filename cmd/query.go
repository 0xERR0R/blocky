package cmd

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/0xERR0R/blocky/api"
	"github.com/0xERR0R/blocky/log"
	"github.com/0xERR0R/blocky/util"

	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

// NewQueryCommand creates new command instance
func NewQueryCommand() *cobra.Command {
	c := &cobra.Command{
		Use:   "query <domain>",
		Args:  cobra.ExactArgs(1),
		Short: "performs DNS query",
		Run:   query,
	}

	c.Flags().StringP("type", "t", "A", "query type (A, AAAA, ...)")

	return c
}

func query(cmd *cobra.Command, args []string) {
	typeFlag, _ := cmd.Flags().GetString("type")
	qType := dns.StringToType[typeFlag]

	if qType == dns.TypeNone {
		log.Log().Fatalf("unknown query type '%s'", typeFlag)
		return
	}

	apiRequest := api.QueryRequest{
		Query: args[0],
		Type:  typeFlag,
	}
	jsonValue, _ := json.Marshal(apiRequest)

	resp, err := http.Post(apiURL(api.PathQueryPath), "application/json", bytes.NewBuffer(jsonValue))

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

	var result api.QueryResult
	err = json.NewDecoder(resp.Body).Decode(&result)

	util.FatalOnError("can't read response: ", err)

	log.Log().Infof("Query result for '%s' (%s):", apiRequest.Query, apiRequest.Type)
	log.Log().Infof("\treason:        %20s", result.Reason)
	log.Log().Infof("\tresponse type: %20s", result.ResponseType)
	log.Log().Infof("\tresponse:      %20s", result.Response)
	log.Log().Infof("\treturn code:   %20s", result.ReturnCode)
}
