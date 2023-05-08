package cmd

import (
	"fmt"
	"net"

	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

const (
	defaultDNSPort = 53
)

func NewHealthcheckCommand() *cobra.Command {
	c := &cobra.Command{
		Use:   "healthcheck",
		Short: "performs healthcheck",
		RunE:  healthcheck,
	}

	c.Flags().Uint16P("port", "p", defaultDNSPort, "healthcheck port 5333")

	return c
}

func healthcheck(cmd *cobra.Command, args []string) error {
	_ = args
	port, _ := cmd.Flags().GetUint16("port")

	c := new(dns.Client)
	c.Net = "tcp"
	m := new(dns.Msg)
	m.SetQuestion("healthcheck.blocky.", dns.TypeA)

	_, _, err := c.Exchange(m, net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", port)))

	if err == nil {
		fmt.Println("OK")
	} else {
		fmt.Println("NOT OK")
	}

	return err
}
