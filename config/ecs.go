package config

import (
	"github.com/0xERR0R/blocky/log"
	"github.com/sirupsen/logrus"
)

const (
	ipv4MaskMax = 32
	ipv6MaskMax = 128
)

type EcsConfig struct {
	UseEcsAsClient bool  `yaml:"useEcsAsClient" default:"false"`
	ForwardEcs     bool  `yaml:"forwardEcs" default:"false"`
	IPv4Mask       uint8 `yaml:"ipv4Mask" default:"0"`
	IPv6Mask       uint8 `yaml:"ipv6Mask" default:"0"`
}

func (c *EcsConfig) IsEnabled() bool {
	return c.UseEcsAsClient || c.IPv4Mask > 0 || c.IPv6Mask > 0
}

func (c *EcsConfig) LogConfig(logger *logrus.Entry) {
	logger.Infof("Use ECS as client = %t", c.UseEcsAsClient)
	logger.Infof("IPv4 netmask      = %d", c.IPv4Mask)
	logger.Infof("IPv6 netmask      = %d", c.IPv6Mask)
}

func (c *EcsConfig) validateConfig() {
	if c.IPv4Mask > ipv4MaskMax {
		log.Log().Errorf("the current value %d of ipv4Mask is above the maxvalue of %d",
			c.IPv4Mask, ipv4MaskMax)

		c.IPv4Mask = 0
	}

	if c.IPv6Mask > ipv6MaskMax {
		log.Log().Errorf("the current value %d of ipv6Mask is above the maxvalue of %d",
			c.IPv6Mask, ipv6MaskMax)

		c.IPv6Mask = 0
	}
}
