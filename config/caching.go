package config

import (
	"time"

	"github.com/sirupsen/logrus"
)

// CachingConfig configuration for domain caching
type CachingConfig struct {
	MinCachingTime        Duration `yaml:"minTime"`
	MaxCachingTime        Duration `yaml:"maxTime"`
	CacheTimeNegative     Duration `yaml:"cacheTimeNegative" default:"30m"`
	MaxItemsCount         int      `yaml:"maxItemsCount"`
	Prefetching           bool     `yaml:"prefetching"`
	PrefetchExpires       Duration `yaml:"prefetchExpires" default:"2h"`
	PrefetchThreshold     int      `yaml:"prefetchThreshold" default:"5"`
	PrefetchMaxItemsCount int      `yaml:"prefetchMaxItemsCount"`
}

// IsEnabled implements `config.ValueLogger`.
func (c *CachingConfig) IsEnabled() bool {
	return c.MaxCachingTime > 0
}

// LogValues implements `config.ValueLogger`.
func (c *CachingConfig) LogValues(logger *logrus.Entry) {
	logger.Infof("minCacheTimeInSec = %d", c.MinCachingTime)

	logger.Infof("maxCacheTimeSec = %d", c.MaxCachingTime)

	logger.Infof("cacheTimeNegative = %s", c.CacheTimeNegative)

	logger.Infof("prefetching = %t", c.Prefetching)

	if c.Prefetching {
		logger.Infof("prefetchExpires = %s", c.PrefetchExpires)
		logger.Infof("prefetchThreshold = %d", c.PrefetchThreshold)
		logger.Infof("prefetchMaxItemsCount = %d", c.PrefetchMaxItemsCount)
	}
}

func (c *CachingConfig) EnablePrefetch() {
	const day = Duration(24 * time.Hour)

	if c.MaxCachingTime.IsZero() {
		// make sure resolver gets enabled
		c.MaxCachingTime = day
	}

	c.Prefetching = true
	c.PrefetchThreshold = 0
}
