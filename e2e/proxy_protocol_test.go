package e2e

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/testcontainers/testcontainers-go"

	"github.com/0xERR0R/blocky/util"
)

var _ = Describe("PROXY protocol behind an nginx stream proxy", func() {
	When("blocky and the nginx stream proxy both use the PROXY protocol", Ordered, func() {
		var (
			e2eNet *testcontainers.DockerNetwork
			blocky testcontainers.Container
			nginx  testcontainers.Container
		)

		BeforeAll(func(ctx context.Context) {
			e2eNet = getRandomNetwork(ctx)

			_, err := createDNSMokkaContainer(ctx, "moka1", e2eNet,
				`A dotquery/NOERROR("A 1.2.3.4 123")`,
				`A dohquery/NOERROR("A 1.2.3.4 123")`)
			Expect(err).Should(Succeed())

			blocky, err = createBlockyContainerFromString(ctx, e2eNet, proxyProtocolBlockyConfig("tls, https"))
			Expect(err).Should(Succeed())

			// nginx must start after blocky so it can resolve the 'blocky' alias.
			nginx, err = createNginxStreamProxyContainer(ctx, e2eNet, true)
			Expect(err).Should(Succeed())
		})

		It("uses the PROXY header source as the client IP for DoT", func(ctx context.Context) {
			Eventually(func() error {
				return queryDoTViaProxy(ctx, nginx, "dotquery.")
			}, "30s", "1s").Should(Succeed())

			nginxIP, err := getContainerNetworkIP(ctx, nginx, e2eNet.Name)
			Expect(err).Should(Succeed())

			clientIP := proxyProtocolClientIP(ctx, blocky, "dotquery")
			Expect(net.ParseIP(clientIP)).ShouldNot(BeNil())
			Expect(clientIP).ShouldNot(Equal(nginxIP),
				"blocky should log the real client IP from the PROXY header, not the proxy's address")
		})

		It("uses the PROXY header source as the client IP for DoH", func(ctx context.Context) {
			Eventually(func() error {
				return queryDoHViaProxy(ctx, nginx, "dohquery.")
			}, "30s", "1s").Should(Succeed())

			nginxIP, err := getContainerNetworkIP(ctx, nginx, e2eNet.Name)
			Expect(err).Should(Succeed())

			clientIP := proxyProtocolClientIP(ctx, blocky, "dohquery")
			Expect(net.ParseIP(clientIP)).ShouldNot(BeNil())
			Expect(clientIP).ShouldNot(Equal(nginxIP),
				"blocky should log the real client IP from the PROXY header, not the proxy's address")
		})
	})

	When("the PROXY protocol is not enabled", Ordered, func() {
		var (
			e2eNet *testcontainers.DockerNetwork
			blocky testcontainers.Container
			nginx  testcontainers.Container
		)

		BeforeAll(func(ctx context.Context) {
			e2eNet = getRandomNetwork(ctx)

			_, err := createDNSMokkaContainer(ctx, "moka1", e2eNet,
				`A dotquery/NOERROR("A 1.2.3.4 123")`,
				`A dohquery/NOERROR("A 1.2.3.4 123")`)
			Expect(err).Should(Succeed())

			blocky, err = createBlockyContainerFromString(ctx, e2eNet, proxyProtocolBlockyConfig(""))
			Expect(err).Should(Succeed())

			nginx, err = createNginxStreamProxyContainer(ctx, e2eNet, false)
			Expect(err).Should(Succeed())
		})

		It("records the proxy address as the client IP for DoT", func(ctx context.Context) {
			Eventually(func() error {
				return queryDoTViaProxy(ctx, nginx, "dotquery.")
			}, "30s", "1s").Should(Succeed())

			nginxIP, err := getContainerNetworkIP(ctx, nginx, e2eNet.Name)
			Expect(err).Should(Succeed())

			clientIP := proxyProtocolClientIP(ctx, blocky, "dotquery")
			Expect(clientIP).Should(Equal(nginxIP),
				"without PROXY protocol blocky sees the connection coming from the proxy")
		})

		It("records the proxy address as the client IP for DoH", func(ctx context.Context) {
			Eventually(func() error {
				return queryDoHViaProxy(ctx, nginx, "dohquery.")
			}, "30s", "1s").Should(Succeed())

			nginxIP, err := getContainerNetworkIP(ctx, nginx, e2eNet.Name)
			Expect(err).Should(Succeed())

			clientIP := proxyProtocolClientIP(ctx, blocky, "dohquery")
			Expect(clientIP).Should(Equal(nginxIP),
				"without PROXY protocol blocky sees the connection coming from the proxy")
		})
	})
})

// proxyProtocolBlockyConfig returns a blocky config listening for DNS (53), DoT (853) and
// HTTPS/DoH (443). It requires the PROXY protocol on the given comma-separated listener families
// (empty disables it) and logs resolved queries to the console, so the recorded client IP can be
// asserted from the container logs.
func proxyProtocolBlockyConfig(families string) string {
	return fmt.Sprintf(`log:
  level: info
ports:
  dns: 53
  tls: 853
  https: 443
  proxyProtocol: [%s]
queryLog:
  type: console
  flushInterval: 1s
upstreams:
  groups:
    default:
      - moka1
`, families)
}

// queryDoTViaProxy sends a DNS-over-TLS query for the given question through the nginx proxy's
// mapped 853 port. The TLS handshake terminates at blocky (nginx is a plain TCP passthrough).
func queryDoTViaProxy(ctx context.Context, nginx testcontainers.Container, question string) error {
	host, port, err := getContainerHostPort(ctx, nginx, "853/tcp")
	if err != nil {
		return err
	}

	c := &dns.Client{
		Net:       "tcp-tls",
		Timeout:   5 * time.Second,
		TLSConfig: &tls.Config{InsecureSkipVerify: true},
	}

	_, _, err = c.Exchange(util.NewMsgWithQuestion(question, dns.Type(dns.TypeA)), net.JoinHostPort(host, port))

	return err
}

// queryDoHViaProxy sends a DNS-over-HTTPS query for the given question through the nginx proxy's
// mapped 443 port.
func queryDoHViaProxy(ctx context.Context, nginx testcontainers.Container, question string) error {
	host, port, err := getContainerHostPort(ctx, nginx, "443/tcp")
	if err != nil {
		return err
	}

	packed, err := util.NewMsgWithQuestion(question, dns.Type(dns.TypeA)).Pack()
	if err != nil {
		return err
	}

	url := "https://" + net.JoinHostPort(host, port) + "/dns-query?dns=" + base64.RawURLEncoding.EncodeToString(packed)

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected DoH status %d", resp.StatusCode)
	}

	return nil
}

var clientIPLogRe = regexp.MustCompile(`client_ip="?([0-9a-fA-F.:]+)`)

// proxyProtocolClientIP polls the blocky container logs for the resolved-query log entry of the
// given question name and returns the client_ip it recorded.
func proxyProtocolClientIP(ctx context.Context, blocky testcontainers.Container, questionName string) string {
	var clientIP string

	Eventually(func() string {
		lines, err := getContainerLogs(ctx, blocky)
		if err != nil {
			return ""
		}

		clientIP = ""

		for _, line := range lines {
			if !strings.Contains(line, "query resolved") || !strings.Contains(line, questionName) {
				continue
			}

			if m := clientIPLogRe.FindStringSubmatch(line); m != nil {
				clientIP = m[1]
			}
		}

		return clientIP
	}, "15s", "500ms").ShouldNot(BeEmpty(),
		"expected a resolved-query log entry for %q with a client_ip field", questionName)

	return clientIP
}
