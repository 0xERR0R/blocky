package e2e

import (
	"context"

	"github.com/0xERR0R/blocky/config"
	. "github.com/0xERR0R/blocky/helpertest"
	"github.com/0xERR0R/blocky/util"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/testcontainers/testcontainers-go"
)

var _ = Describe("Hosts file resolver", func() {
	var (
		e2eNet *testcontainers.DockerNetwork
		blocky testcontainers.Container
		err    error
	)

	BeforeEach(func(ctx context.Context) {
		e2eNet = getRandomNetwork(ctx)

		_, err = createDNSMokkaContainer(ctx, "moka", e2eNet,
			`A fallback.example/NOERROR("A 9.9.9.9 300")`,
		)
		Expect(err).Should(Succeed())
	})

	Describe("Local mounted hosts file", func() {
		When("a hosts file is mounted into the container", func() {
			BeforeEach(func(ctx context.Context) {
				hostsFile := createTempFile(
					"192.168.1.1 myhost.example",
					"10.0.0.1 server.example",
				)

				confFile := createTempFile(
					"upstreams:",
					"  groups:",
					"    default:",
					"      - moka",
					"hostsFile:",
					"  sources:",
					"    - /app/hosts.txt",
					"  hostsTTL: 5m",
				)

				cfg, cfgErr := config.LoadConfig(confFile, true)
				Expect(cfgErr).Should(Succeed())

				req := buildBlockyContainerRequest(confFile)
				req.Files = append(req.Files, testcontainers.ContainerFile{
					HostFilePath:      hostsFile,
					ContainerFilePath: "/app/hosts.txt",
					FileMode:          700,
				})

				ctx, cancel := context.WithTimeout(ctx, 2*startupTimeout)
				defer cancel()

				blocky, err = startContainerWithNetwork(ctx, req, "blocky", e2eNet)
				Expect(err).Should(Succeed())
				Expect(checkBlockyReadiness(ctx, cfg, blocky)).Should(Succeed())
			})

			It("should resolve domains from the hosts file", func(ctx context.Context) {
				msg := util.NewMsgWithQuestion("myhost.example.", A)
				Expect(doDNSRequest(ctx, blocky, msg)).
					Should(
						SatisfyAll(
							BeDNSRecord("myhost.example.", A, "192.168.1.1"),
							HaveTTL(BeNumerically("==", 300)),
						))
			})

			It("should resolve multiple hosts from the file", func(ctx context.Context) {
				msg := util.NewMsgWithQuestion("server.example.", A)
				Expect(doDNSRequest(ctx, blocky, msg)).
					Should(
						SatisfyAll(
							BeDNSRecord("server.example.", A, "10.0.0.1"),
							HaveTTL(BeNumerically("==", 300)),
						))
			})
		})
	})

	Describe("HTTP-served hosts file", func() {
		When("hosts file is served via HTTP", func() {
			BeforeEach(func(ctx context.Context) {
				_, err = createHTTPServerContainer(ctx, "httpserver", e2eNet, "hosts.txt",
					"172.16.0.1 webserver.example",
				)
				Expect(err).Should(Succeed())

				blocky, err = createBlockyContainer(ctx, e2eNet,
					"upstreams:",
					"  groups:",
					"    default:",
					"      - moka",
					"hostsFile:",
					"  sources:",
					"    - http://httpserver:8080/hosts.txt",
				)
				Expect(err).Should(Succeed())
			})

			It("should resolve domains from the HTTP-served hosts file", func(ctx context.Context) {
				msg := util.NewMsgWithQuestion("webserver.example.", A)
				Expect(doDNSRequest(ctx, blocky, msg)).
					Should(BeDNSRecord("webserver.example.", A, "172.16.0.1"))
			})
		})
	})

	Describe("Custom TTL", func() {
		When("hostsTTL is configured", func() {
			BeforeEach(func(ctx context.Context) {
				_, err = createHTTPServerContainer(ctx, "httpserver", e2eNet, "hosts.txt",
					"192.168.1.1 myhost.example",
				)
				Expect(err).Should(Succeed())

				blocky, err = createBlockyContainer(ctx, e2eNet,
					"upstreams:",
					"  groups:",
					"    default:",
					"      - moka",
					"hostsFile:",
					"  sources:",
					"    - http://httpserver:8080/hosts.txt",
					"  hostsTTL: 2m",
				)
				Expect(err).Should(Succeed())
			})

			It("should use the configured TTL for hosts file responses", func(ctx context.Context) {
				msg := util.NewMsgWithQuestion("myhost.example.", A)
				Expect(doDNSRequest(ctx, blocky, msg)).
					Should(
						SatisfyAll(
							BeDNSRecord("myhost.example.", A, "192.168.1.1"),
							HaveTTL(BeNumerically("==", 120)),
						))
			})
		})
	})

	Describe("Loopback filtering", func() {
		When("filterLoopback is enabled", func() {
			BeforeEach(func(ctx context.Context) {
				_, err = createHTTPServerContainer(ctx, "httpserver", e2eNet, "hosts.txt",
					"127.0.0.1 loopback.example",
					"192.168.1.1 normal.example",
				)
				Expect(err).Should(Succeed())

				blocky, err = createBlockyContainer(ctx, e2eNet,
					"upstreams:",
					"  groups:",
					"    default:",
					"      - moka",
					"hostsFile:",
					"  sources:",
					"    - http://httpserver:8080/hosts.txt",
					"  filterLoopback: true",
				)
				Expect(err).Should(Succeed())
			})

			It("should not resolve loopback entries", func(ctx context.Context) {
				msg := util.NewMsgWithQuestion("loopback.example.", A)
				resp, err := doDNSRequest(ctx, blocky, msg)
				Expect(err).Should(Succeed())
				Expect(resp.Answer).Should(BeEmpty())
			})

			It("should resolve non-loopback entries normally", func(ctx context.Context) {
				msg := util.NewMsgWithQuestion("normal.example.", A)
				Expect(doDNSRequest(ctx, blocky, msg)).
					Should(BeDNSRecord("normal.example.", A, "192.168.1.1"))
			})
		})
	})

	Describe("Exact host resolution", func() {
		When("a hosts file entry exists", func() {
			BeforeEach(func(ctx context.Context) {
				_, err = createHTTPServerContainer(ctx, "httpserver", e2eNet, "hosts.txt",
					"192.168.1.1 myhost.example",
				)
				Expect(err).Should(Succeed())

				blocky, err = createBlockyContainer(ctx, e2eNet,
					"upstreams:",
					"  groups:",
					"    default:",
					"      - moka",
					"hostsFile:",
					"  sources:",
					"    - http://httpserver:8080/hosts.txt",
				)
				Expect(err).Should(Succeed())
			})

			It("should resolve exact hosts file entries", func(ctx context.Context) {
				msg := util.NewMsgWithQuestion("myhost.example.", A)
				Expect(doDNSRequest(ctx, blocky, msg)).
					Should(BeDNSRecord("myhost.example.", A, "192.168.1.1"))
			})
		})
	})
})
