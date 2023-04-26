package config

import "github.com/sirupsen/logrus"

type EcsConfig struct {
	UseEcsAsClient bool  `yaml:"useEcsAsClient" default:"false"`
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
