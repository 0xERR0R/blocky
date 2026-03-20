package config

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/0xERR0R/blocky/log"
	"github.com/fsnotify/fsnotify"
)

const reloadCooldownMs = 2000

type ConfigWatcher struct {
	cancel     context.CancelFunc
	lastReload atomic.Int64
}

func NewConfigWatcher(
	ctx context.Context,
	configPath string,
	cfg ConfigWatch,
	onReload func() error,
) (*ConfigWatcher, error) {
	ctx, cancel := context.WithCancel(ctx)
	cw := &ConfigWatcher{cancel: cancel}

	// Wrap onReload with cooldown to prevent double-trigger.
	// Uses millisecond granularity and CompareAndSwap to close the TOCTOU race
	// between the fsnotify and polling goroutines.
	wrappedReload := func() error {
		now := time.Now().UnixMilli()

		for {
			last := cw.lastReload.Load()
			if now-last < reloadCooldownMs {
				return nil
			}

			if cw.lastReload.CompareAndSwap(last, now) {
				break
			}
		}

		return onReload()
	}

	// Try fsnotify
	fsWatcher, err := cw.startFsnotify(ctx, configPath, wrappedReload)
	if err != nil {
		log.PrefixedLog("config_watcher").Warnf("fsnotify unavailable, using polling only: %v", err)
	} else if fsWatcher != nil {
		go func() {
			<-ctx.Done()
			fsWatcher.Close()
		}()
	}

	// Start polling as safety net
	if cfg.Interval.ToDuration() > 0 {
		go cw.poll(ctx, configPath, cfg.Interval.ToDuration(), wrappedReload)
	}

	return cw, nil
}

func (cw *ConfigWatcher) startFsnotify(
	ctx context.Context,
	configPath string,
	onReload func() error,
) (*fsnotify.Watcher, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	watchPath := configPath
	info, err := os.Stat(configPath)
	if err != nil {
		watcher.Close()

		return nil, err
	}
	if !info.IsDir() {
		watchPath = filepath.Dir(configPath)
	}

	if err := watcher.Add(watchPath); err != nil {
		watcher.Close()

		return nil, err
	}

	// When watching a single file we monitor its parent directory (editors often
	// replace the file atomically). Filter events to the actual config file so
	// that unrelated changes in the same directory don't trigger a reload.
	filter := newFsnotifyFilter(!info.IsDir(), configPath)

	go fsnotifyLoop(ctx, watcher, filter, onReload)

	return watcher, nil
}

// fsnotifyFilter decides whether an fsnotify event is relevant.
type fsnotifyFilter struct {
	isFileWatch   bool
	absConfigPath string
}

func newFsnotifyFilter(isFileWatch bool, configPath string) fsnotifyFilter {
	return fsnotifyFilter{
		isFileWatch:   isFileWatch,
		absConfigPath: filepath.Clean(configPath),
	}
}

func (f fsnotifyFilter) isRelevant(event fsnotify.Event) bool {
	if !event.Has(fsnotify.Write) && !event.Has(fsnotify.Create) &&
		!event.Has(fsnotify.Rename) && !event.Has(fsnotify.Remove) {
		return false
	}

	if f.isFileWatch && filepath.Clean(event.Name) != f.absConfigPath {
		return false
	}

	return true
}

func fsnotifyLoop(ctx context.Context, watcher *fsnotify.Watcher, filter fsnotifyFilter, onReload func() error) {
	logger := log.PrefixedLog("config_watcher")

	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}

			if filter.isRelevant(event) {
				logger.Info("config file change detected (fsnotify)")

				if err := onReload(); err != nil {
					logger.Errorf("config reload failed: %v", err)
				}
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}

			logger.Errorf("fsnotify error: %v", err)
		}
	}
}

func (cw *ConfigWatcher) poll(
	ctx context.Context,
	configPath string,
	interval time.Duration,
	onReload func() error,
) {
	logger := log.PrefixedLog("config_watcher")
	lastMod := getConfigModTime(configPath)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			mod := getConfigModTime(configPath)
			if mod.After(lastMod) {
				lastMod = mod
				logger.Info("config file change detected (polling)")
				if err := onReload(); err != nil {
					logger.Errorf("config reload failed: %v", err)
				}
			}
		}
	}
}

func getConfigModTime(path string) time.Time {
	info, err := os.Stat(path)
	if err != nil {
		return time.Time{}
	}
	if !info.IsDir() {
		return info.ModTime()
	}
	var latest time.Time
	filepath.Walk(path, func(p string, fi os.FileInfo, err error) error { //nolint:errcheck
		if err != nil {
			return nil //nolint:nilerr
		}
		if !fi.IsDir() && fi.ModTime().After(latest) {
			latest = fi.ModTime()
		}

		return nil
	})

	return latest
}

func (cw *ConfigWatcher) Close() {
	cw.cancel()
}
