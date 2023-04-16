package config

import (
	"fmt"
	"os"

	"github.com/moby/moby/libnetwork/resolvconf"
)

type ResolvconfConfig struct {
	Enable bool `yaml:"enable"`
}

func getDNSServerFromResolvConf() ([]Upstream, error) {
	resolvconfFile, err := os.ReadFile(resolvconf.Path())
	if err != nil {
		return nil, fmt.Errorf("can't read resolv.conf file: %w", err)
	}

	resolvconfServers := resolvconf.GetNameservers(resolvconfFile, resolvconf.IP)
	upstreams := make([]Upstream, 0, len(resolvconfServers))

	for _, server := range resolvconfServers {
		upstream, err := ParseUpstream(server)
		if err != nil {
			return nil, err
		}

		upstreams = append(upstreams, upstream)
	}

	return upstreams, nil
}

func (c *ParallelBestConfig) AddResolvconfToConfig() error {
	upstreams, err := getDNSServerFromResolvConf()
	if err != nil {
		return err
	}

	if c.ExternalResolvers == nil {
		c.ExternalResolvers = make(ParallelBestMapping)
	}

	c.ExternalResolvers["default"] = append(c.ExternalResolvers["default"], upstreams...)

	return nil
}
