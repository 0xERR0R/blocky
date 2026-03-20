package server

import (
	"context"
	"os"
	"path/filepath"

	"github.com/0xERR0R/blocky/config"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Server reload", func() {
	var sut *Server

	minimalConfig := func() *config.Config {
		return &config.Config{
			Upstreams: config.Upstreams{
				Groups: map[string][]config.Upstream{
					"default": {{Net: config.NetProtocolTcpUdp, Host: "1.1.1.1", Port: 53}},
				},
			},
			Blocking: config.Blocking{BlockType: "zeroIp"},
			Ports: config.Ports{
				DOHPath: "/dns-query",
			},
		}
	}

	When("concurrent reload is attempted", func() {
		BeforeEach(func(ctx context.Context) {
			var err error
			sut, err = NewServer(ctx, minimalConfig(), "")
			Expect(err).Should(Succeed())
		})

		It("should reject with TryLock", func() {
			sut.reloadMu.Lock()
			defer sut.reloadMu.Unlock()

			err := sut.Reload()
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("reload already in progress"))
		})
	})

	When("config path is invalid", func() {
		BeforeEach(func(ctx context.Context) {
			var err error
			sut, err = NewServer(ctx, minimalConfig(), "/nonexistent/path/config.yml")
			Expect(err).Should(Succeed())
		})

		It("should return error", func() {
			err := sut.Reload()
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("config reload failed"))
		})
	})

	When("config file is valid", func() {
		var cfgPath string

		BeforeEach(func(ctx context.Context) {
			tmpDir := GinkgoT().TempDir()
			cfgPath = filepath.Join(tmpDir, "config.yml")

			cfgContent := `
upstreams:
  groups:
    default:
      - 1.1.1.1
blocking:
  blockType: zeroIp
ports:
  dohPath: /dns-query
`
			Expect(os.WriteFile(cfgPath, []byte(cfgContent), 0o600)).Should(Succeed())

			var err error
			sut, err = NewServer(ctx, minimalConfig(), cfgPath)
			Expect(err).Should(Succeed())
		})

		It("should reload successfully", func() {
			err := sut.Reload()
			Expect(err).Should(Succeed())

			newCfg := sut.ActiveConfig()
			Expect(newCfg).ShouldNot(BeNil())
		})
	})
})
