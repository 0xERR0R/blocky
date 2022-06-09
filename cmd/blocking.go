package cmd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/0xERR0R/blocky/api"
	"github.com/0xERR0R/blocky/log"
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
		RunE:    enableBlocking,
	})

	disableCommand := &cobra.Command{
		Use:     "disable",
		Aliases: []string{"off"},
		Args:    cobra.NoArgs,
		Short:   "Disable blocking for certain duration",
		RunE:    disableBlocking,
	}
	disableCommand.Flags().DurationP("duration", "d", 0, "duration in min")
	disableCommand.Flags().StringArrayP("groups", "g", []string{}, "blocking groups to disable")
	c.AddCommand(disableCommand)

	c.AddCommand(&cobra.Command{
		Use:   "status",
		Args:  cobra.NoArgs,
		Short: "Print the status of blocking resolver",
		RunE:  statusBlocking,
	})

	return c
}

func enableBlocking(_ *cobra.Command, _ []string) error {
	resp, err := http.Get(apiURL(api.PathBlockingEnablePath))
	if err != nil {
		return fmt.Errorf("can't execute %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		log.Log().Info("OK")
	} else {
		return fmt.Errorf("response NOK, Status: %s", resp.Status)
	}

	return nil
}

func disableBlocking(cmd *cobra.Command, _ []string) error {
	duration, _ := cmd.Flags().GetDuration("duration")
	groups, _ := cmd.Flags().GetStringArray("groups")

	resp, err := http.Get(fmt.Sprintf("%s?duration=%s&groups=%s",
		apiURL(api.PathBlockingDisablePath), duration, strings.Join(groups, ",")))
	if err != nil {
		return fmt.Errorf("can't execute %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		log.Log().Info("OK")
	} else {
		return fmt.Errorf("response NOK, Status: %s", resp.Status)
	}

	return nil
}

func statusBlocking(_ *cobra.Command, _ []string) error {
	resp, err := http.Get(apiURL(api.PathBlockingStatusPath))
	if err != nil {
		return fmt.Errorf("can't execute %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("response NOK, Status: %s", resp.Status)
	}

	var result api.BlockingStatus
	err = json.NewDecoder(resp.Body).Decode(&result)

	if err != nil {
		return fmt.Errorf("can't parse response %w", err)
	}

	if result.Enabled {
		log.Log().Info("blocking enabled")
	} else {
		if result.AutoEnableInSec == 0 {
			log.Log().Infof("blocking disabled for groups: %s", strings.Join(result.DisabledGroups, "; "))
		} else {
			log.Log().Infof("blocking disabled for groups: %s, for %d seconds",
				strings.Join(result.DisabledGroups, "; "), result.AutoEnableInSec)
		}
	}

	return nil
}
