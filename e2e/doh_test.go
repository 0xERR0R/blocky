package e2e

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/testcontainers/testcontainers-go"
)

var _ = Describe("DoH functionality", func() {
	var (
		e2eNet *testcontainers.DockerNetwork
		blocky testcontainers.Container
		err    error
	)

	BeforeEach(func(ctx context.Context) {
		// Create a fresh network for each test
		e2eNet = getRandomNetwork(ctx)
	})

	Describe("Custom DoH path", func() {
		Context("when a custom DoH path is configured", func() {
			BeforeEach(func(ctx context.Context) {
				_, err = createDNSMokkaContainer(ctx, "moka1", e2eNet, `A google/NOERROR("A 1.2.3.4 123")`)
				Expect(err).Should(Succeed())

				blocky, err = createBlockyContainer(ctx, e2eNet,
					"upstreams:",
					"  groups:",
					"    default:",
					"      - moka1",
					"ports:",
					"  http: 4000",
					"  dohPath: /my-doh-path",
				)
				Expect(err).Should(Succeed())
			})

			It("serves DoH content on the custom path and not on the default path", func(ctx context.Context) {
				host, port, err := getContainerHostPort(ctx, blocky, "4000/tcp")
				Expect(err).Should(Succeed())
				url := "http://" + net.JoinHostPort(host, port)

				By("serving DNS-over-HTTPS on the custom path", func() {
					Eventually(http.Get).WithArguments(url +
						"/my-doh-path?dns=q80BAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB").Should(HaveHTTPStatus(http.StatusOK))
				})

				By("not serving DNS-over-HTTPS on the default path", func() {
					Eventually(http.Get).WithArguments(url +
						"/dns-query?dns=q80BAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB").Should(HaveHTTPStatus(http.StatusNotFound))
				})
			})
		})

		Context("when a custom DoH path is not configured", func() {
			BeforeEach(func(ctx context.Context) {
				_, err = createDNSMokkaContainer(ctx, "moka1", e2eNet, `A google/NOERROR("A 1.2.3.4 123")`)
				Expect(err).Should(Succeed())

				blocky, err = createBlockyContainer(ctx, e2eNet,
					"upstreams:",
					"  groups:",
					"    default:",
					"      - moka1",
					"ports:",
					"  http: 4000",
				)
				Expect(err).Should(Succeed())
			})

			It("serves DoH content on the default path", func(ctx context.Context) {
				host, port, err := getContainerHostPort(ctx, blocky, "4000/tcp")
				Expect(err).Should(Succeed())
				url := "http://" + net.JoinHostPort(host, port)

				Eventually(http.Get).WithArguments(url +
					"/dns-query?dns=q80BAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB").Should(HaveHTTPStatus(http.StatusOK))
			})
		})

		Context("when a custom DoH path is configured with HTTPS", func() {
			BeforeEach(func(ctx context.Context) {
				_, err = createDNSMokkaContainer(ctx, "moka1", e2eNet, `A google/NOERROR("A 1.2.3.4 123")`)
				Expect(err).Should(Succeed())

				blocky, err = createBlockyContainer(ctx, e2eNet,
					"upstreams:",
					"  groups:",
					"    default:",
					"      - moka1",
					"ports:",
					"  https: 4000",
					"  dohPath: /my-doh-path",
				)
				Expect(err).Should(Succeed())
			})

			It("serves DoH content on the custom path with HTTPS", func(ctx context.Context) {
				host, port, err := getContainerHostPort(ctx, blocky, "4000/tcp")
				Expect(err).Should(Succeed())
				url := "https://" + net.JoinHostPort(host, port)

				// create a http client with disabled certificate check
				tr := &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				}
				client := &http.Client{Transport: tr}

				By("serving DNS-over-HTTPS on the custom path", func() {
					Eventually(client.Get).WithArguments(url +
						"/my-doh-path?dns=q80BAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB").Should(HaveHTTPStatus(http.StatusOK))
				})

				By("not serving DNS-over-HTTPS on the default path", func() {
					Eventually(client.Get).WithArguments(url +
						"/dns-query?dns=q80BAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB").Should(HaveHTTPStatus(http.StatusNotFound))
				})
			})
		})
	})
})
