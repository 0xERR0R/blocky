package config

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("ConfigWatcher", func() {
	var tmpDir string

	BeforeEach(func() {
		tmpDir = GinkgoT().TempDir()
	})

	When("watching a single file", func() {
		It("should detect file changes", func(ctx context.Context) {
			cfgFile := filepath.Join(tmpDir, "config.yml")
			Expect(os.WriteFile(cfgFile, []byte("initial"), 0o644)).Should(Succeed())

			reloadCalled := make(chan struct{}, 10)
			watcher, err := NewConfigWatcher(ctx, cfgFile, ConfigWatch{
				Enabled:  true,
				Interval: Duration(500 * time.Millisecond),
			}, func() error {
				reloadCalled <- struct{}{}

				return nil
			})
			Expect(err).Should(Succeed())
			defer watcher.Close()

			time.Sleep(100 * time.Millisecond)
			Expect(os.WriteFile(cfgFile, []byte("changed"), 0o644)).Should(Succeed())

			Eventually(reloadCalled, "5s").Should(Receive())
		})
	})

	When("watching a directory", func() {
		It("should detect changes to any file", func(ctx context.Context) {
			cfgDir := filepath.Join(tmpDir, "conf.d")
			Expect(os.MkdirAll(cfgDir, 0o755)).Should(Succeed())
			Expect(os.WriteFile(filepath.Join(cfgDir, "a.yml"), []byte("a"), 0o644)).Should(Succeed())

			reloadCalled := make(chan struct{}, 10)
			watcher, err := NewConfigWatcher(ctx, cfgDir, ConfigWatch{
				Enabled:  true,
				Interval: Duration(500 * time.Millisecond),
			}, func() error {
				reloadCalled <- struct{}{}

				return nil
			})
			Expect(err).Should(Succeed())
			defer watcher.Close()

			time.Sleep(100 * time.Millisecond)
			Expect(os.WriteFile(filepath.Join(cfgDir, "a.yml"), []byte("changed"), 0o644)).Should(Succeed())

			Eventually(reloadCalled, "5s").Should(Receive())
		})
	})

	When("reload callback returns error", func() {
		It("should continue watching", func(ctx context.Context) {
			cfgFile := filepath.Join(tmpDir, "config.yml")
			Expect(os.WriteFile(cfgFile, []byte("initial"), 0o644)).Should(Succeed())

			calls := make(chan struct{}, 10)
			// Reset cooldown so second call works
			watcher, err := NewConfigWatcher(ctx, cfgFile, ConfigWatch{
				Enabled:  true,
				Interval: Duration(500 * time.Millisecond),
			}, func() error {
				calls <- struct{}{}

				return errors.New("reload failed")
			})
			Expect(err).Should(Succeed())
			defer watcher.Close()

			Expect(os.WriteFile(cfgFile, []byte("v2"), 0o644)).Should(Succeed())
			Eventually(calls, "5s").Should(Receive())
		})
	})
})
