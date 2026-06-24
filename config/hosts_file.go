package config

import (
	"fmt"
	"log/slog"

	. "github.com/0xERR0R/blocky/config/migration"
	"github.com/0xERR0R/blocky/log"
)

type HostsFile struct {
	// Host files to load (e.g. /etc/hosts); supports local paths, URLs, and inline content.
	Sources []BytesSource `yaml:"sources"`
	// TTL for DNS records resolved from host files.
	HostsTTL Duration `default:"1h" yaml:"hostsTTL"`
	// If true, loopback addresses (127.0.0.0/8 and ::1) from host files are ignored.
	FilterLoopback bool `yaml:"filterLoopback"`
	// Controls how host files are loaded and periodically refreshed.
	Loading SourceLoading `yaml:"loading"`

	// Deprecated options
	Deprecated struct {
		RefreshPeriod *Duration    `yaml:"refreshPeriod"`
		Filepath      *BytesSource `yaml:"filePath"`
	} `yaml:",inline"`
}

func (c *HostsFile) migrate(logger *slog.Logger) bool {
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
func (c *HostsFile) LogConfig(logger *slog.Logger) {
	logger.Info(fmt.Sprintf("TTL: %s", c.HostsTTL))
	logger.Info(fmt.Sprintf("filter loopback addresses: %t", c.FilterLoopback))

	logger.Info("loading:")
	log.WithIndent(logger, "  ", c.Loading.LogConfig)

	logger.Info("sources:")

	for _, source := range c.Sources {
		logger.Info(fmt.Sprintf("  - %s", source))
	}
}
