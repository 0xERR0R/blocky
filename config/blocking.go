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
	// Named groups of block-list sources (URLs, file paths, or inline content).
	Denylists map[string][]BytesSource `yaml:"denylists"`
	// Named groups of allow-list sources; entries here take precedence over denylists in the same group.
	Allowlists map[string][]BytesSource `yaml:"allowlists"`
	// Named time-based schedules that can gate when list groups are active.
	Schedules map[string]Schedule `yaml:"schedules"`
	// Maps each list group name to the schedule(s) that control when it is active.
	ListSchedules map[string][]string `yaml:"listSchedules"`
	// Maps client identifiers (name, IP, CIDR) to the list groups that apply to them.
	ClientGroupsBlock map[string][]string `yaml:"clientGroupsBlock"`
	// Response for blocked A/AAAA queries: zeroIP (0.0.0.0/::), nxDomain, or custom IPs; other types get NXDOMAIN.
	BlockType string `default:"ZEROIP" yaml:"blockType"`
	// TTL of blocked responses; how long clients cache the block before querying the domain again.
	BlockTTL Duration `default:"6h" yaml:"blockTTL"`
	// Controls how block/allow lists are loaded and periodically refreshed.
	Loading SourceLoading `yaml:"loading"`

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

	for key, val := range c.ClientGroupsBlock {
		logger.Infof("  %s = %v", key, val)
	}

	if len(c.Schedules) > 0 {
		logger.Info("schedules:")

		for name, sched := range c.Schedules {
			if sched.Start == "" && sched.End == "" {
				logger.Infof("  %s: all day (weekdays: %v)", name, sched.Weekdays)
			} else {
				logger.Infof("  %s: %s - %s (weekdays: %v)", name, sched.Start, sched.End, sched.Weekdays)
			}
		}
	}

	if len(c.ListSchedules) > 0 {
		logger.Info("listSchedules:")

		for list, scheds := range c.ListSchedules {
			logger.Infof("  %s = %v", list, scheds)
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

	for name, sched := range c.Schedules {
		if err := sched.validate(); err != nil {
			return fmt.Errorf("schedule '%s': %w", name, err)
		}

		// Map values are not addressable, so validate()'s mutations are lost
		// unless we write the compiled struct back.
		c.Schedules[name] = sched
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

	for clientGroupKey, clientGroupLists := range c.ClientGroupsBlock {
		for _, listKey := range clientGroupLists {
			if !listKeys[listKey] {
				availableKeys := slices.Sorted(maps.Keys(listKeys))

				return fmt.Errorf("clientGroupsBlock '%s' references undefined allowlist or denylist '%s'. Available: %s",
					clientGroupKey, listKey, strings.Join(availableKeys, ", "))
			}
		}
	}

	// Validate listSchedules references
	for listName, schedNames := range c.ListSchedules {
		if !listKeys[listName] {
			availableKeys := slices.Sorted(maps.Keys(listKeys))

			return fmt.Errorf("listSchedules references undefined list '%s'. Available: %s",
				listName, strings.Join(availableKeys, ", "))
		}

		for _, schedName := range schedNames {
			if _, ok := c.Schedules[schedName]; !ok {
				availableSchedules := slices.Sorted(maps.Keys(c.Schedules))

				return fmt.Errorf("listSchedules '%s' references undefined schedule '%s'. Available: %s",
					listName, schedName, strings.Join(availableSchedules, ", "))
			}
		}
	}

	return nil
}
