package config

import (
	"time"

	"github.com/sirupsen/logrus"
)

// Caching configuration for domain caching
type Caching struct {
	MinCachingTime        Duration `yaml:"minTime"`
	MaxCachingTime        Duration `yaml:"maxTime"`
	CacheTimeNegative     Duration `yaml:"cacheTimeNegative" default:"30m"`
	MaxItemsCount         int      `yaml:"maxItemsCount"`
	Prefetching           bool     `yaml:"prefetching"`
	PrefetchExpires       Duration `yaml:"prefetchExpires" default:"2h"`
	PrefetchThreshold     int      `yaml:"prefetchThreshold" default:"5"`
	PrefetchMaxItemsCount int      `yaml:"prefetchMaxItemsCount"`
}

// IsEnabled implements `config.Configurable`.
func (c *Caching) IsEnabled() bool {
	return c.MaxCachingTime.IsAtLeastZero()
}

// LogConfig implements `config.Configurable`.
func (c *Caching) LogConfig(logger *logrus.Entry) {
	logger.Infof("minTime = %s", c.MinCachingTime)
	logger.Infof("maxTime = %s", c.MaxCachingTime)
	logger.Infof("cacheTimeNegative = %s", c.CacheTimeNegative)

	if c.Prefetching {
		logger.Infof("prefetching:")
		logger.Infof("  expires   = %s", c.PrefetchExpires)
		logger.Infof("  threshold = %d", c.PrefetchThreshold)
		logger.Infof("  maxItems  = %d", c.PrefetchMaxItemsCount)
	} else {
		logger.Debug("prefetching: disabled")
	}
}

func (c *Caching) EnablePrefetch() {
	const day = Duration(24 * time.Hour)

	if !c.IsEnabled() {
		// make sure resolver gets enabled
		c.MaxCachingTime = day
	}

	c.Prefetching = true
	c.PrefetchThreshold = 0
}
