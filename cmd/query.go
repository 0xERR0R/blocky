package cmd

import (
	"blocky/api"
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/miekg/dns"
	"github.com/spf13/cobra"

	log "github.com/sirupsen/logrus"
)

//nolint:gochecknoinits
func init() {
	rootCmd.AddCommand(queryCmd)
	queryCmd.Flags().StringP("type", "t", "A", "query type (A, AAAA, ...)")
}

//nolint:gochecknoglobals
var queryCmd = &cobra.Command{
	Use:   "query <domain>",
	Args:  cobra.ExactArgs(1),
	Short: "performs DNS query",
	Run:   query,
}

func query(cmd *cobra.Command, args []string) {
	typeFlag, _ := cmd.Flags().GetString("type")
	qType := dns.StringToType[typeFlag]

	if qType == dns.TypeNone {
		log.Fatalf("unknown query type '%s'", typeFlag)
	}

	apiRequest := api.QueryRequest{
		Query: args[0],
		Type:  typeFlag,
	}
	jsonValue, _ := json.Marshal(apiRequest)

	resp, err := http.Post(apiURL(api.BlockingQueryPath), "application/json", bytes.NewBuffer(jsonValue))

	if err != nil {
		log.Fatal("can't execute", err)

		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		log.Fatalf("NOK: %s %s", resp.Status, string(body))

		return
	}

	var result api.QueryResult
	err = json.NewDecoder(resp.Body).Decode(&result)

	if err != nil {
		log.Fatal("can't read response: ", err)

		return
	}

	log.Infof("Query result for '%s' (%s):", apiRequest.Query, apiRequest.Type)
	log.Infof("\treason:        %20s", result.Reason)
	log.Infof("\tresponse type: %20s", result.ResponseType)
	log.Infof("\tresponse:      %20s", result.Response)
	log.Infof("\treturn code:   %20s", result.ReturnCode)
}
