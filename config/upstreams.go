package config

import (
	"github.com/0xERR0R/blocky/log"
	"github.com/sirupsen/logrus"
)

const UpstreamDefaultCfgName = "default"

// QUICConfig holds QUIC-specific upstream settings.
type QUICConfig struct {
	MaxIdleTimeout  Duration `default:"30s" yaml:"maxIdleTimeout"`
	KeepAlivePeriod Duration `default:"15s" yaml:"keepAlivePeriod"`
}

// Upstreams upstream servers configuration
type Upstreams struct {
	Init      Init             `yaml:"init"`
	Timeout   Duration         `default:"2s"            yaml:"timeout"` // always > 0
	Groups    UpstreamGroups   `yaml:"groups"`
	Strategy  UpstreamStrategy `default:"parallel_best" yaml:"strategy"`
	UserAgent string           `yaml:"userAgent"`
	QUIC      QUICConfig       `yaml:"quic"`
}

type UpstreamGroups map[string][]Upstream

func (c *Upstreams) hasQuicUpstream() bool {
	for _, upstreams := range c.Groups {
		for _, u := range upstreams {
			if u.Net == NetProtocolQuic {
				return true
			}
		}
	}

	return false
}

func (c *Upstreams) validate(logger *logrus.Entry) {
	defaults := mustDefault[Upstreams]()

	if !c.Timeout.IsAboveZero() {
		logger.Warnf("upstreams.timeout <= 0, setting to %s", defaults.Timeout)
		c.Timeout = defaults.Timeout
	}

	if c.hasQuicUpstream() {
		if !c.QUIC.MaxIdleTimeout.IsAboveZero() {
			logger.Warnf("upstreams.quic.maxIdleTimeout <= 0, setting to %s", defaults.QUIC.MaxIdleTimeout)
			c.QUIC.MaxIdleTimeout = defaults.QUIC.MaxIdleTimeout
		}

		if !c.QUIC.KeepAlivePeriod.IsAboveZero() {
			logger.Warnf("upstreams.quic.keepAlivePeriod <= 0, setting to %s", defaults.QUIC.KeepAlivePeriod)
			c.QUIC.KeepAlivePeriod = defaults.QUIC.KeepAlivePeriod
		}

		if c.QUIC.KeepAlivePeriod.ToDuration() >= c.QUIC.MaxIdleTimeout.ToDuration() {
			logger.Warn("upstreams.quic.keepAlivePeriod >= maxIdleTimeout, keep-alive won't prevent idle timeout")
		}
	}
}

// IsEnabled implements `config.Configurable`.
func (c *Upstreams) IsEnabled() bool {
	return len(c.Groups) != 0
}

// LogConfig implements `config.Configurable`.
func (c *Upstreams) LogConfig(logger *logrus.Entry) {
	logger.Info("init:")
	log.WithIndent(logger, "  ", c.Init.LogConfig)

	logger.Info("timeout: ", c.Timeout)
	logger.Info("strategy: ", c.Strategy)
	logger.Info("groups:")

	for name, upstreams := range c.Groups {
		logger.Infof("  %s:", name)

		for _, upstream := range upstreams {
			logger.Infof("    - %s", upstream)
		}
	}

	if c.hasQuicUpstream() {
		logger.Info("quic:")
		logger.Info("  maxIdleTimeout: ", c.QUIC.MaxIdleTimeout)
		logger.Info("  keepAlivePeriod: ", c.QUIC.KeepAlivePeriod)
	}
}

// UpstreamGroup represents the config for one group (upstream branch)
type UpstreamGroup struct {
	Upstreams

	Name string // group name
}

// NewUpstreamGroup creates an UpstreamGroup with the given name and upstreams.
//
// The upstreams from `cfg.Groups` are ignored.
func NewUpstreamGroup(name string, cfg Upstreams, upstreams []Upstream) UpstreamGroup {
	group := UpstreamGroup{
		Name:      name,
		Upstreams: cfg,
	}

	group.Groups = UpstreamGroups{name: upstreams}

	return group
}

func (c *UpstreamGroup) GroupUpstreams() []Upstream {
	return c.Groups[c.Name]
}

// IsEnabled implements `config.Configurable`.
func (c *UpstreamGroup) IsEnabled() bool {
	return len(c.GroupUpstreams()) != 0
}

// LogConfig implements `config.Configurable`.
func (c *UpstreamGroup) LogConfig(logger *logrus.Entry) {
	logger.Info("group: ", c.Name)
	logger.Info("upstreams:")

	for _, upstream := range c.GroupUpstreams() {
		logger.Infof("  - %s", upstream)
	}
}
