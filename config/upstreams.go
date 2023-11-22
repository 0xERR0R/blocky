package config

import (
	"github.com/0xERR0R/blocky/log"
	"github.com/sirupsen/logrus"
)

const UpstreamDefaultCfgName = "default"

// Upstreams upstream servers configuration
type Upstreams struct {
	Init      Init             `yaml:"init"`
	Timeout   Duration         `yaml:"timeout" default:"2s"` // always > 0
	Groups    UpstreamGroups   `yaml:"groups"`
	Strategy  UpstreamStrategy `yaml:"strategy" default:"parallel_best"`
	UserAgent string           `yaml:"userAgent"`
}

type UpstreamGroups map[string][]Upstream

func (c *Upstreams) validate(logger *logrus.Entry) {
	defaults := mustDefault[Upstreams]()

	if !c.Timeout.IsAboveZero() {
		logger.Warnf("upstreams.timeout <= 0, setting to %s", defaults.Timeout)
		c.Timeout = defaults.Timeout
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
