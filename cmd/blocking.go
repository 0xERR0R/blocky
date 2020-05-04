package cmd

import (
	"blocky/api"
	"encoding/json"
	"fmt"
	"net/http"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

//nolint:gochecknoinits
func init() {
	rootCmd.AddCommand(blockingCmd)

	blockingCmd.AddCommand(&cobra.Command{
		Use:     "enable",
		Args:    cobra.NoArgs,
		Aliases: []string{"on"},
		Short:   "Enable blocking",
		Run:     enableBlocking,
	})

	disableCommand := &cobra.Command{
		Use:     "disable",
		Aliases: []string{"off"},
		Args:    cobra.NoArgs,
		Short:   "Disable blocking for certain duration",
		Run:     disableBlocking,
	}
	disableCommand.Flags().DurationP("duration", "d", 0, "duration in min")
	blockingCmd.AddCommand(disableCommand)

	blockingCmd.AddCommand(&cobra.Command{
		Use:   "status",
		Args:  cobra.NoArgs,
		Short: "Print the status of blocking resolver",
		Run:   statusBlocking,
	})
}

//nolint:gochecknoglobals
var blockingCmd = &cobra.Command{
	Use:     "blocking",
	Aliases: []string{"block"},
	Short:   "Control status of blocking resolver",
}

func enableBlocking(_ *cobra.Command, _ []string) {
	resp, err := http.Get(apiURL(api.BlockingEnablePath))
	if err != nil {
		log.Fatal("can't execute", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		log.Info("OK")
	} else {
		log.Fatal("NOK: ", resp.Status)
	}
}

func disableBlocking(cmd *cobra.Command, _ []string) {
	duration, _ := cmd.Flags().GetDuration("duration")

	resp, err := http.Get(fmt.Sprintf("%s?duration=%s", apiURL(api.BlockingDisablePath), duration))
	if err != nil {
		log.Fatal("can't execute", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		log.Info("OK")
	} else {
		log.Fatal("NOK: ", resp.Status)
	}
}

func statusBlocking(_ *cobra.Command, _ []string) {
	resp, err := http.Get(apiURL(api.BlockingStatusPath))
	if err != nil {
		log.Fatal("can't execute", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Fatal("NOK: ", resp.Status)
		return
	}

	var result api.BlockingStatus
	err = json.NewDecoder(resp.Body).Decode(&result)

	if err != nil {
		log.Fatal("can't read response: ", err)
	}

	if result.Enabled {
		log.Info("blocking enabled")
	} else {
		if result.AutoEnableInSec == 0 {
			log.Info("blocking disabled")
		} else {
			log.Infof("blocking disabled for %d seconds", result.AutoEnableInSec)
		}
	}
}
