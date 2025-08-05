package config

import (
	"net/url"
	"strings"

	"github.com/0xERR0R/blocky/log"
	"github.com/sirupsen/logrus"
)

// QueryLog configuration for the query logging
type QueryLog struct {
	Target           string          `yaml:"target"`
	Type             QueryLogType    `yaml:"type"`
	LogRetentionDays uint64          `yaml:"logRetentionDays"`
	CreationAttempts int             `default:"3"             yaml:"creationAttempts"`
	CreationCooldown Duration        `default:"2s"            yaml:"creationCooldown"`
	Fields           []QueryLogField `yaml:"fields"`
	FlushInterval    Duration        `default:"30s"           yaml:"flushInterval"`
	Ignore           QueryLogIgnore  `yaml:"ignore"`
}

type QueryLogIgnore struct {
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
	// Make sure there's a scheme, otherwise the user is parsed as the scheme
	targetStr := c.Target
	if !strings.Contains(targetStr, "://") {
		targetStr = c.Type.String() + "://" + targetStr
	}

	target, err := url.Parse(targetStr)
	if err != nil {
		return c.Target
	}

	pass, ok := target.User.Password()
	if !ok {
		return c.Target
	}

	return strings.ReplaceAll(c.Target, pass, secretObfuscator)
}
