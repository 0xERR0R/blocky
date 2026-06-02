package config

import (
	"net/url"
	"strings"

	"github.com/0xERR0R/blocky/log"
	"github.com/sirupsen/logrus"
)

// QueryLog configuration for the query logging
type QueryLog struct {
	// Directory for CSV log files, or database URL for mysql/postgresql/timescale targets.
	Target Secret `yaml:"target"`
	// Log target type: mysql, postgresql, timescale, csv, csv-client, console, or none.
	Type QueryLogType `yaml:"type"`
	// Delete log entries older than this many days. 0 disables retention cleanup.
	LogRetentionDays uint64 `yaml:"logRetentionDays"`
	// Maximum number of attempts to create the query log writer on startup.
	CreationAttempts int `default:"3" yaml:"creationAttempts"`
	// Delay between query log writer creation attempts.
	CreationCooldown Duration `default:"2s" yaml:"creationCooldown"`
	// Which fields to include in log entries; defaults to all available fields.
	Fields []QueryLogField `yaml:"fields"`
	// Interval at which buffered log entries are flushed to the external database.
	FlushInterval Duration `default:"30s" yaml:"flushInterval"`
	// Rules to suppress certain queries from being logged.
	Ignore QueryLogIgnore `yaml:"ignore"`
}

type QueryLogIgnore struct {
	// If true, queries resolved as Special Use Domain Names (SUDN) are not logged.
	SUDN bool `default:"false" yaml:"sudn"`
}

// SetDefaults implements `defaults.Setter`.
func (c *QueryLog) SetDefaults() {
	// Since the default depends on the enum values, set it dynamically
	// to avoid having to repeat the values in the annotation.
	c.Fields = QueryLogFieldValues()
}

// IsEnabled implements `config.Configurable`.
func (c *QueryLog) IsEnabled() bool {
	return c.Type != QueryLogTypeNone
}

// LogConfig implements `config.Configurable`.
func (c *QueryLog) LogConfig(logger *logrus.Entry) {
	logger.Infof("type: %s", c.Type)

	if c.Target != "" {
		logger.Infof("target: %s", c.censoredTarget())
	}

	logger.Infof("logRetentionDays: %d", c.LogRetentionDays)
	logger.Debugf("creationAttempts: %d", c.CreationAttempts)
	logger.Debugf("creationCooldown: %s", c.CreationCooldown)
	logger.Infof("flushInterval: %s", c.FlushInterval)
	logger.Infof("fields: %s", c.Fields)

	logger.Infof("ignore:")
	log.WithIndent(logger, "  ", func(e *logrus.Entry) {
		logger.Infof("sudn: %t", c.Ignore.SUDN)
	})
}

func (c *QueryLog) censoredTarget() string {
	target := c.Target.Reveal()

	// Make sure there's a scheme, otherwise the user is parsed as the scheme
	targetStr := target
	if !strings.Contains(targetStr, "://") {
		targetStr = c.Type.String() + "://" + targetStr
	}

	parsed, err := url.Parse(targetStr)
	if err != nil {
		return target
	}

	pass, ok := parsed.User.Password()
	if !ok {
		return target
	}

	return strings.ReplaceAll(target, pass, secretObfuscator)
}
