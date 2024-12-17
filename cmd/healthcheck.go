package cmd

import (
	"fmt"
	"net"

	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

const (
	defaultDNSPort   = 53
	defaultIPAddress = "127.0.0.1"
)

func NewHealthcheckCommand() *cobra.Command {
	c := &cobra.Command{
		Use:   "healthcheck",
		Short: "performs healthcheck",
		RunE:  healthcheck,
	}

	c.Flags().Uint16P("port", "p", defaultDNSPort, "blocky port")
	c.Flags().StringP("bindip", "b", defaultIPAddress, "blocky host binding ip address")

	return c
}

func healthcheck(cmd *cobra.Command, args []string) error {
	_ = args
	port, _ := cmd.Flags().GetUint16("port")
	bindIP, _ := cmd.Flags().GetString("bindip")

	c := new(dns.Client)
	c.Net = "tcp"
	m := new(dns.Msg)
	m.SetQuestion("healthcheck.blocky.", dns.TypeA)

	_, _, err := c.Exchange(m, net.JoinHostPort(bindIP, fmt.Sprintf("%d", port)))

	if err == nil {
		fmt.Println("OK")
	} else {
		fmt.Println("NOT OK")
	}

	return err
}
