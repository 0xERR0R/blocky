package config

import (
	. "github.com/0xERR0R/blocky/config/migration"
	"github.com/0xERR0R/blocky/log"
	"github.com/sirupsen/logrus"
)

type HostsFile struct {
	Sources        []BytesSource `yaml:"sources"`
	HostsTTL       Duration      `yaml:"hostsTTL" default:"1h"`
	FilterLoopback bool          `yaml:"filterLoopback"`
	Loading        SourceLoading `yaml:"loading"`

	// Deprecated options
	Deprecated struct {
		RefreshPeriod *Duration    `yaml:"refreshPeriod"`
		Filepath      *BytesSource `yaml:"filePath"`
	} `yaml:",inline"`
}

func (c *HostsFile) migrate(logger *logrus.Entry) bool {
	return Migrate(logger, "hostsFile", c.Deprecated, map[string]Migrator{
		"refreshPeriod": Move(To("loading.refreshPeriod", &c.Loading)),
		"filePath": Apply(To("sources", c), func(value BytesSource) {
			c.Sources = append(c.Sources, value)
		}),
	})
}

// IsEnabled implements `config.Configurable`.
func (c *HostsFile) IsEnabled() bool {
	return len(c.Sources) != 0
}

// LogConfig implements `config.Configurable`.
func (c *HostsFile) LogConfig(logger *logrus.Entry) {
	logger.Infof("TTL: %s", c.HostsTTL)
	logger.Infof("filter loopback addresses: %t", c.FilterLoopback)

	logger.Info("loading:")
	log.WithIndent(logger, "  ", c.Loading.LogConfig)

	logger.Info("sources:")

	for _, source := range c.Sources {
		logger.Infof("  - %s", source)
	}
}
