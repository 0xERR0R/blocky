package cmd

import (
	"blocky/api"
	"blocky/util"
	"encoding/json"
	"fmt"
	"net/http"

	"blocky/log"

	"github.com/spf13/cobra"
)

func newBlockingCommand() *cobra.Command {
	c := &cobra.Command{
		Use:     "blocking",
		Aliases: []string{"block"},
		Short:   "Control status of blocking resolver",
	}
	c.AddCommand(&cobra.Command{
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
	c.AddCommand(disableCommand)

	c.AddCommand(&cobra.Command{
		Use:   "status",
		Args:  cobra.NoArgs,
		Short: "Print the status of blocking resolver",
		Run:   statusBlocking,
	})

	return c
}

func enableBlocking(_ *cobra.Command, _ []string) {
	resp, err := http.Get(apiURL(api.PathBlockingEnablePath))
	if err != nil {
		log.Log().Fatal("can't execute", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		log.Log().Info("OK")
	} else {
		log.Log().Fatal("NOK: ", resp.Status)
	}
}

func disableBlocking(cmd *cobra.Command, _ []string) {
	duration, _ := cmd.Flags().GetDuration("duration")

	resp, err := http.Get(fmt.Sprintf("%s?duration=%s", apiURL(api.PathBlockingDisablePath), duration))
	if err != nil {
		log.Log().Fatal("can't execute", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		log.Log().Info("OK")
	} else {
		log.Log().Fatal("NOK: ", resp.Status)
	}
}

func statusBlocking(_ *cobra.Command, _ []string) {
	resp, err := http.Get(apiURL(api.PathBlockingStatusPath))
	if err != nil {
		log.Log().Fatal("can't execute", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Log().Fatal("NOK: ", resp.Status)
		return
	}

	var result api.BlockingStatus
	err = json.NewDecoder(resp.Body).Decode(&result)

	util.FatalOnError("can't read response: ", err)

	if result.Enabled {
		log.Log().Info("blocking enabled")
	} else {
		if result.AutoEnableInSec == 0 {
			log.Log().Info("blocking disabled")
		} else {
			log.Log().Infof("blocking disabled for %d seconds", result.AutoEnableInSec)
		}
	}
}
