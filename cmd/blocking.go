package cmd

import (
	"context"
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
	client, err := api.NewClientWithResponses(apiURL())
	if err != nil {
		return fmt.Errorf("can't create client: %w", err)
	}

	resp, err := client.EnableBlockingWithResponse(context.Background())
	if err != nil {
		return fmt.Errorf("can't execute %w", err)
	}

	return printOkOrError(resp, string(resp.Body))
}

func disableBlocking(cmd *cobra.Command, _ []string) error {
	duration, _ := cmd.Flags().GetDuration("duration")
	groups, _ := cmd.Flags().GetStringArray("groups")

	durationString := duration.String()
	groupsString := strings.Join(groups, ",")

	client, err := api.NewClientWithResponses(apiURL())
	if err != nil {
		return fmt.Errorf("can't create client: %w", err)
	}

	resp, err := client.DisableBlockingWithResponse(context.Background(), &api.DisableBlockingParams{
		Duration: &durationString,
		Groups:   &groupsString,
	})
	if err != nil {
		return fmt.Errorf("can't execute %w", err)
	}

	return printOkOrError(resp, string(resp.Body))
}

func statusBlocking(_ *cobra.Command, _ []string) error {
	client, err := api.NewClientWithResponses(apiURL())
	if err != nil {
		return fmt.Errorf("can't create client: %w", err)
	}

	resp, err := client.BlockingStatusWithResponse(context.Background())
	if err != nil {
		return fmt.Errorf("can't execute %w", err)
	}

	if resp.StatusCode() != http.StatusOK {
		return fmt.Errorf("response NOK, Status: %s", resp.Status())
	}

	if err != nil {
		return fmt.Errorf("can't parse response %w", err)
	}

	if resp.JSON200.Enabled {
		log.Log().Info("blocking enabled")
	} else {
		var groupNames string
		if resp.JSON200.DisabledGroups != nil {
			groupNames = strings.Join(*resp.JSON200.DisabledGroups, "; ")
		}
		if resp.JSON200.AutoEnableInSec == nil || *resp.JSON200.AutoEnableInSec == 0 {
			log.Log().Infof("blocking disabled for groups: %s", groupNames)
		} else {
			log.Log().Infof("blocking disabled for groups: '%s', for %d seconds",
				groupNames, *resp.JSON200.AutoEnableInSec)
		}
	}

	return nil
}
