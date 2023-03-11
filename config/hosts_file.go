package config

import (
	"github.com/sirupsen/logrus"
)

type HostsFileConfig struct {
	Filepath       string   `yaml:"filePath"`
	HostsTTL       Duration `yaml:"hostsTTL" default:"1h"`
	RefreshPeriod  Duration `yaml:"refreshPeriod" default:"1h"`
	FilterLoopback bool     `yaml:"filterLoopback"`
}

// IsEnabled implements `config.ValueLogger`.
func (c *HostsFileConfig) IsEnabled() bool {
	return len(c.Filepath) != 0
}

// LogValues implements `config.ValueLogger`.
func (c *HostsFileConfig) LogValues(logger *logrus.Entry) {
	logger.Infof("file path: %s", c.Filepath)
	logger.Infof("TTL: %d", c.HostsTTL.SecondsU32())
	logger.Infof("refresh period: %s", c.RefreshPeriod)
	logger.Infof("filter loopback addresses: %t", c.FilterLoopback)
}
