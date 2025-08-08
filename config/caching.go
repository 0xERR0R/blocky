package config

import (
	"time"

	"github.com/sirupsen/logrus"
)

// Caching configuration for domain caching
type Caching struct {
	MinCachingTime        Duration `yaml:"minTime"`
	MaxCachingTime        Duration `yaml:"maxTime"`
	CacheTimeNegative     Duration `default:"30m"                yaml:"cacheTimeNegative"`
	MaxItemsCount         int      `yaml:"maxItemsCount"`
	Prefetching           bool     `yaml:"prefetching"`
	PrefetchExpires       Duration `default:"2h"                 yaml:"prefetchExpires"`
	PrefetchThreshold     int      `default:"5"                  yaml:"prefetchThreshold"`
	PrefetchMaxItemsCount int      `yaml:"prefetchMaxItemsCount"`
	Exclude               []string `yaml:"exclude"`
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
	logger.Infof("exclude:")
	for _, val := range c.Exclude {
		logger.Infof("- %v", val)
	}

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
