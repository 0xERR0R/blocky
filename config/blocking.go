package config

import (
	"strings"

	"github.com/0xERR0R/blocky/log"
	"github.com/sirupsen/logrus"
)

// BlockingConfig configuration for query blocking
type BlockingConfig struct {
	BlackLists        map[string][]string `yaml:"blackLists"`
	WhiteLists        map[string][]string `yaml:"whiteLists"`
	ClientGroupsBlock map[string][]string `yaml:"clientGroupsBlock"`
	BlockType         string              `yaml:"blockType" default:"ZEROIP"`
	BlockTTL          Duration            `yaml:"blockTTL" default:"6h"`
	DownloadTimeout   Duration            `yaml:"downloadTimeout" default:"60s"`
	DownloadAttempts  uint                `yaml:"downloadAttempts" default:"3"`
	DownloadCooldown  Duration            `yaml:"downloadCooldown" default:"1s"`
	RefreshPeriod     Duration            `yaml:"refreshPeriod" default:"4h"`
	// Deprecated
	FailStartOnListError  bool              `yaml:"failStartOnListError" default:"false"`
	ProcessingConcurrency uint              `yaml:"processingConcurrency" default:"4"`
	StartStrategy         StartStrategyType `yaml:"startStrategy" default:"blocking"`
}

// IsEnabled implements `config.Configurable`.
func (c *BlockingConfig) IsEnabled() bool {
	return len(c.ClientGroupsBlock) != 0
}

// IsEnabled implements `config.Configurable`.
func (c *BlockingConfig) LogConfig(logger *logrus.Entry) {
	logger.Info("clientGroupsBlock:")

	for key, val := range c.ClientGroupsBlock {
		logger.Infof("  %s = %v", key, val)
	}

	logger.Infof("blockType = %s", c.BlockType)

	if c.BlockType != "NXDOMAIN" {
		logger.Infof("blockTTL = %s", c.BlockTTL)
	}

	logger.Infof("downloadTimeout = %s", c.DownloadTimeout)

	logger.Infof("failStartOnListError = %t", c.FailStartOnListError)

	if c.RefreshPeriod > 0 {
		logger.Infof("refresh = every %s", c.RefreshPeriod)
	} else {
		logger.Debug("refresh = disabled")
	}

	logger.Info("blacklist:")
	log.WithIndent(logger, "  ", func(logger *logrus.Entry) {
		c.logListGroups(logger, c.BlackLists)
	})

	logger.Info("whitelist:")
	log.WithIndent(logger, "  ", func(logger *logrus.Entry) {
		c.logListGroups(logger, c.WhiteLists)
	})
}

func (c *BlockingConfig) logListGroups(logger *logrus.Entry, listGroups map[string][]string) {
	for group, links := range listGroups {
		logger.Infof("%s:", group)

		for _, link := range links {
			if idx := strings.IndexRune(link, '\n'); idx != -1 && idx < len(link) { // found and not last char
				link = link[:idx] // first line only

				logger.Infof("   - %s [...]", link)
			} else {
				logger.Infof("   - %s", link)
			}
		}
	}
}
