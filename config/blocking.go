package config

import (
	. "github.com/0xERR0R/blocky/config/migration"
	"github.com/0xERR0R/blocky/log"
	"github.com/sirupsen/logrus"
)

// Blocking configuration for query blocking
type Blocking struct {
	BlackLists        map[string][]BytesSource `yaml:"blackLists"`
	WhiteLists        map[string][]BytesSource `yaml:"whiteLists"`
	ClientGroupsBlock map[string][]string      `yaml:"clientGroupsBlock"`
	BlockType         string                   `yaml:"blockType" default:"ZEROIP"`
	BlockTTL          Duration                 `yaml:"blockTTL" default:"6h"`
	Loading           SourceLoadingConfig      `yaml:"loading"`

	// Deprecated options
	Deprecated struct {
		DownloadTimeout       *Duration          `yaml:"downloadTimeout"`
		DownloadAttempts      *uint              `yaml:"downloadAttempts"`
		DownloadCooldown      *Duration          `yaml:"downloadCooldown"`
		RefreshPeriod         *Duration          `yaml:"refreshPeriod"`
		FailStartOnListError  *bool              `yaml:"failStartOnListError"`
		ProcessingConcurrency *uint              `yaml:"processingConcurrency"`
		StartStrategy         *StartStrategyType `yaml:"startStrategy"`
		MaxErrorsPerFile      *int               `yaml:"maxErrorsPerFile"`
	} `yaml:",inline"`
}

func (c *Blocking) migrate(logger *logrus.Entry) bool {
	return Migrate(logger, "blocking", c.Deprecated, map[string]Migrator{
		"downloadTimeout":  Move(To("loading.downloads.timeout", &c.Loading.Downloads)),
		"downloadAttempts": Move(To("loading.downloads.attempts", &c.Loading.Downloads)),
		"downloadCooldown": Move(To("loading.downloads.cooldown", &c.Loading.Downloads)),
		"refreshPeriod":    Move(To("loading.refreshPeriod", &c.Loading)),
		"failStartOnListError": Apply(To("loading.strategy", &c.Loading), func(oldValue bool) {
			if oldValue {
				c.Loading.Strategy = StartStrategyTypeFailOnError
			}
		}),
		"processingConcurrency": Move(To("loading.concurrency", &c.Loading)),
		"startStrategy":         Move(To("loading.strategy", &c.Loading)),
		"maxErrorsPerFile":      Move(To("loading.maxErrorsPerSource", &c.Loading)),
	})
}

// IsEnabled implements `config.Configurable`.
func (c *Blocking) IsEnabled() bool {
	return len(c.ClientGroupsBlock) != 0
}

// LogConfig implements `config.Configurable`.
func (c *Blocking) LogConfig(logger *logrus.Entry) {
	logger.Info("clientGroupsBlock:")

	for key, val := range c.ClientGroupsBlock {
		logger.Infof("  %s = %v", key, val)
	}

	logger.Infof("blockType = %s", c.BlockType)

	if c.BlockType != "NXDOMAIN" {
		logger.Infof("blockTTL = %s", c.BlockTTL)
	}

	logger.Info("loading:")
	log.WithIndent(logger, "  ", c.Loading.LogConfig)

	logger.Info("blacklist:")
	log.WithIndent(logger, "  ", func(logger *logrus.Entry) {
		c.logListGroups(logger, c.BlackLists)
	})

	logger.Info("whitelist:")
	log.WithIndent(logger, "  ", func(logger *logrus.Entry) {
		c.logListGroups(logger, c.WhiteLists)
	})
}

func (c *Blocking) logListGroups(logger *logrus.Entry, listGroups map[string][]BytesSource) {
	for group, sources := range listGroups {
		logger.Infof("%s:", group)

		for _, source := range sources {
			logger.Infof("   - %s", source)
		}
	}
}
