package cmd

import (
	"blocky/api"
	"blocky/util"
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"

	"blocky/log"

	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

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
		log.Logger.Fatalf("unknown query type '%s'", typeFlag)
		return
	}

	apiRequest := api.QueryRequest{
		Query: args[0],
		Type:  typeFlag,
	}
	jsonValue, _ := json.Marshal(apiRequest)

	resp, err := http.Post(apiURL(api.PathQueryPath), "application/json", bytes.NewBuffer(jsonValue))

	if err != nil {
		log.Logger.Fatal("can't execute", err)

		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		log.Logger.Fatalf("NOK: %s %s", resp.Status, string(body))

		return
	}

	var result api.QueryResult
	err = json.NewDecoder(resp.Body).Decode(&result)

	util.FatalOnError("can't read response: ", err)

	log.Logger.Infof("Query result for '%s' (%s):", apiRequest.Query, apiRequest.Type)
	log.Logger.Infof("\treason:        %20s", result.Reason)
	log.Logger.Infof("\tresponse type: %20s", result.ResponseType)
	log.Logger.Infof("\tresponse:      %20s", result.Response)
	log.Logger.Infof("\treturn code:   %20s", result.ReturnCode)
}
