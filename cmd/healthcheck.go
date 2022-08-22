package cmd

import (
	"context"
	"net"
	"time"

	"github.com/spf13/cobra"
)

func NewHealthcheckCommand() *cobra.Command {
	c := &cobra.Command{
		Use:   "healthcheck <port>",
		Args:  cobra.ExactArgs(1),
		Short: "performs healthcheck",
		RunE:  healthcheck,
	}

	c.Flags().IntP("port", "p", 53, "healthcheck port 5333")

	return c
}

func healthcheck(cmd *cobra.Command, args []string) error {
	port, err := cmd.Flags().GetInt("port")
	if err != nil {
		port = 53
	}

	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: 2 * time.Second,
			}
			return d.DialContext(ctx, network, "127.0.0.1")
		},
	}

	_, err := resolver.LookupHost(context.Background(), "healthcheck.blocky")

	return err
}
