package config

import (
	"github.com/sirupsen/logrus"
)

type HostsFileConfig struct {
	Filepath       string   `yaml:"filePath"`
	HostsTTL       Duration `yaml:"hostsTTL" default:"\"1h\""`
	RefreshPeriod  Duration `yaml:"refreshPeriod" default:"\"1h\""`
	FilterLoopback bool     `yaml:"filterLoopback"`
}

func (c *HostsFileConfig) LogValues(log *logrus.Entry) {
	if c.Filepath == "" {
		return
	}

	log.Infof("file path: %s", c.Filepath)
	log.Infof("TTL: %d", c.HostsTTL.SecondsU32())
	log.Infof("refresh period: %s", c.RefreshPeriod)
	log.Infof("filter loopback addresses: %t", c.FilterLoopback)
}
