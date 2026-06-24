package config

import (
	"fmt"
	"log/slog"
	"time"
)

// Caching configuration for domain caching
type Caching struct {
	// Minimum TTL for cached entries; if the response TTL is smaller, this value is used instead.
	MinCachingTime Duration `yaml:"minTime"`
	// Maximum TTL for cached entries. If <0, caching is disabled. If 0, the response TTL is used.
	MaxCachingTime Duration `yaml:"maxTime"`
	// TTL for negative responses (NXDOMAIN / empty). Use -1 to disable caching of negative results.
	CacheTimeNegative Duration `default:"30m" yaml:"cacheTimeNegative"`
	// Maximum number of cache entries (soft limit). 0 means unlimited.
	MaxItemsCount int `yaml:"maxItemsCount"`
	// If true, blocky preloads DNS results for frequently queried names before they expire.
	Prefetching bool `yaml:"prefetching"`
	// Time window used to track query frequency for prefetch eligibility.
	PrefetchExpires Duration `default:"2h" yaml:"prefetchExpires"`
	// Minimum number of queries within prefetchExpires required to trigger prefetching.
	PrefetchThreshold int `default:"5" yaml:"prefetchThreshold"`
	// Maximum number of domains tracked for prefetching (soft limit). 0 means unlimited.
	PrefetchMaxItemsCount int `yaml:"prefetchMaxItemsCount"`
	// Regex list of domains that are never cached.
	Exclude []string `yaml:"exclude"`
}

// IsEnabled implements `config.Configurable`.
func (c *Caching) IsEnabled() bool {
	return c.MaxCachingTime.IsAtLeastZero()
}

// LogConfig implements `config.Configurable`.
func (c *Caching) LogConfig(logger *slog.Logger) {
	logger.Info(fmt.Sprintf("minTime = %s", c.MinCachingTime))
	logger.Info(fmt.Sprintf("maxTime = %s", c.MaxCachingTime))
	logger.Info(fmt.Sprintf("cacheTimeNegative = %s", c.CacheTimeNegative))
	logger.Info("exclude:")
	for _, val := range c.Exclude {
		logger.Info(fmt.Sprintf("- %v", val))
	}

	if c.Prefetching {
		logger.Info("prefetching:")
		logger.Info(fmt.Sprintf("  expires   = %s", c.PrefetchExpires))
		logger.Info(fmt.Sprintf("  threshold = %d", c.PrefetchThreshold))
		logger.Info(fmt.Sprintf("  maxItems  = %d", c.PrefetchMaxItemsCount))
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
