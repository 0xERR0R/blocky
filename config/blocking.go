package config

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	. "github.com/0xERR0R/blocky/config/migration"
	"github.com/0xERR0R/blocky/log"
	"github.com/sirupsen/logrus"
)

// Blocking configuration for query blocking
type Blocking struct {
	Denylists         map[string][]BytesSource     `yaml:"denylists"`
	Allowlists        map[string][]BytesSource     `yaml:"allowlists"`
	Schedules         map[string]Schedule          `yaml:"schedules"`
	ClientGroupsBlock map[string][]BlockGroupEntry `yaml:"clientGroupsBlock"`
	BlockType         string                       `default:"ZEROIP"         yaml:"blockType"`
	BlockTTL          Duration                     `default:"6h"             yaml:"blockTTL"`
	Loading           SourceLoading                `yaml:"loading"`

	// Deprecated options
	Deprecated struct {
		BlackLists            *map[string][]BytesSource `yaml:"blackLists"`
		WhiteLists            *map[string][]BytesSource `yaml:"whiteLists"`
		DownloadTimeout       *Duration                 `yaml:"downloadTimeout"`
		DownloadAttempts      *uint                     `yaml:"downloadAttempts"`
		DownloadCooldown      *Duration                 `yaml:"downloadCooldown"`
		RefreshPeriod         *Duration                 `yaml:"refreshPeriod"`
		FailStartOnListError  *bool                     `yaml:"failStartOnListError"`
		ProcessingConcurrency *uint                     `yaml:"processingConcurrency"`
		StartStrategy         *InitStrategy             `yaml:"startStrategy"`
		MaxErrorsPerFile      *int                      `yaml:"maxErrorsPerFile"`
	} `yaml:",inline"`
}

func (c *Blocking) migrate(logger *logrus.Entry) bool {
	return Migrate(logger, "blocking", c.Deprecated, map[string]Migrator{
		"blackLists":       Move(To("denylists", c)),
		"whiteLists":       Move(To("allowlists", c)),
		"downloadTimeout":  Move(To("loading.downloads.timeout", &c.Loading.Downloads)),
		"downloadAttempts": Move(To("loading.downloads.attempts", &c.Loading.Downloads)),
		"downloadCooldown": Move(To("loading.downloads.cooldown", &c.Loading.Downloads)),
		"refreshPeriod":    Move(To("loading.refreshPeriod", &c.Loading)),
		"failStartOnListError": Apply(To("loading.strategy", &c.Loading.Init), func(oldValue bool) {
			if oldValue {
				c.Loading.Strategy = InitStrategyFailOnError
			}
		}),
		"processingConcurrency": Move(To("loading.concurrency", &c.Loading)),
		"startStrategy":         Move(To("loading.strategy", &c.Loading.Init)),
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

	for key, entries := range c.ClientGroupsBlock {
		for _, entry := range entries {
			if entry.Schedule != "" {
				logger.Infof("  %s = %s (schedule: %s)", key, entry.List, entry.Schedule)
			} else {
				logger.Infof("  %s = %s", key, entry.List)
			}
		}
	}

	if len(c.Schedules) > 0 {
		logger.Info("schedules:")

		for name, sched := range c.Schedules {
			logger.Infof("  %s: %s - %s (weekdays: %v)", name, sched.Start, sched.End, sched.Weekdays)
		}
	}

	logger.Infof("blockType = %s", c.BlockType)
	logger.Infof("blockTTL = %s", c.BlockTTL)

	logger.Info("loading:")
	log.WithIndent(logger, "  ", c.Loading.LogConfig)

	logger.Info("denylists:")
	log.WithIndent(logger, "  ", func(logger *logrus.Entry) {
		c.logListGroups(logger, c.Denylists)
	})

	logger.Info("allowlists:")
	log.WithIndent(logger, "  ", func(logger *logrus.Entry) {
		c.logListGroups(logger, c.Allowlists)
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

// validate checks blocking configuration for validity
func (c *Blocking) validate() error {
	if !c.IsEnabled() {
		return nil
	}

	// Validate schedules
	for name, sched := range c.Schedules {
		if err := sched.validate(); err != nil {
			return fmt.Errorf("schedule '%s': %w", name, err)
		}
	}

	// Validate if all allowlists and denylists referenced
	// in clientGroupsBlock are defined.
	listKeys := make(map[string]bool, len(c.Denylists)+len(c.Allowlists))
	for group := range c.Denylists {
		listKeys[group] = true
	}
	for group := range c.Allowlists {
		listKeys[group] = true
	}

	for clientGroupKey, entries := range c.ClientGroupsBlock {
		for _, entry := range entries {
			if !listKeys[entry.List] {
				availableKeys := slices.Sorted(maps.Keys(listKeys))

				return fmt.Errorf("clientGroupsBlock '%s' references undefined allowlist or denylist '%s'. Available: %s",
					clientGroupKey, entry.List, strings.Join(availableKeys, ", "))
			}

			if entry.Schedule != "" {
				if _, ok := c.Schedules[entry.Schedule]; !ok {
					availableSchedules := slices.Sorted(maps.Keys(c.Schedules))

					return fmt.Errorf("clientGroupsBlock '%s' references undefined schedule '%s'. Available: %s",
						clientGroupKey, entry.Schedule, strings.Join(availableSchedules, ", "))
				}
			}
		}
	}

	return nil
}
