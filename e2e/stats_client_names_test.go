package e2e

import (
	"context"
	"net"

	"github.com/0xERR0R/blocky/api"
	. "github.com/0xERR0R/blocky/helpertest"
	"github.com/0xERR0R/blocky/util"

	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/testcontainers/testcontainers-go"
)

// Regression test for https://github.com/0xERR0R/blocky/issues/2152
//
// Queries that blocky answers on its own above the client-name lookup (a filtered query type,
// a non-FQDN name) must be attributed to the same client as every other query of that client.
// Before the fix they carried no client name, so the statistics counted them under the raw
// client IP and the same client appeared twice in the top-clients list: once by name, once by
// IP.
//
// The client identity is pinned with ecs.useAsClient (as in the #2140 test): the connecting
// test client is some docker network address, never 10.0.0.1, so a query can only be counted
// as "ecsclient" if the ECS subnet was adopted as the client and its name was resolved - for
// filtered and non-FQDN queries alike.
var _ = Describe("Statistics client identity (issue #2152)", func() {
	var (
		e2eNet *testcontainers.DockerNetwork
		blocky testcontainers.Container
		err    error
	)

	BeforeEach(func(ctx context.Context) {
		e2eNet = getRandomNetwork(ctx)

		_, err = createDNSMokkaContainer(ctx, "moka", e2eNet,
			`A example.com/NOERROR("A 1.2.3.4 300")`)
		Expect(err).Should(Succeed())

		blocky, err = createBlockyContainerFromString(ctx, e2eNet, dedent(`
			log:
			  level: warn
			upstreams:
			  groups:
			    default:
			      - moka
			clientLookup:
			  clients:
			    ecsclient:
			      - 10.0.0.1
			ecs:
			  useAsClient: true
			filtering:
			  queryTypes:
			    - AAAA
			fqdnOnly:
			  enable: true
			statistics:
			  enable: true
			ports:
			  http: 4000
			`))
		Expect(err).Should(Succeed())
	})

	It("counts filtered and non-FQDN queries under the client name, not the client IP",
		func(ctx context.Context) {
			host, port, err := getContainerHostPort(ctx, blocky, "4000/tcp")
			Expect(err).Should(Succeed())
			statsURL := "http://" + net.JoinHostPort(host, port) + "/api/stats"

			ecsQuery := func(question string, qType dns.Type) (*dns.Msg, error) {
				msg := util.NewMsgWithQuestion(question, qType)
				addECSOption(msg, net.ParseIP("10.0.0.1"))

				return doDNSRequest(ctx, blocky, msg)
			}

			By("sending a query blocky forwards upstream", func() {
				Expect(ecsQuery("example.com.", A)).Should(BeDNSRecord("example.com.", A, "1.2.3.4"))
			})

			By("sending a query the filtering resolver answers", func() {
				resp, err := ecsQuery("example.com.", AAAA)
				Expect(err).Should(Succeed())
				Expect(resp.Rcode).Should(Equal(dns.RcodeSuccess))
				Expect(resp.Answer).Should(BeEmpty())
			})

			By("sending a query the fqdnOnly resolver answers", func() {
				// blocky answers NOTFQDN with a message that carries neither the request id nor
				// the question section, which the DNS client rejects as an id mismatch (the
				// fqdnOnly e2e test tolerates the same error). The query still reaches blocky
				// and is counted, which is what this test is about.
				resp, err := ecsQuery("myserver.", A)
				if err == nil {
					Expect(resp.Rcode).Should(Equal(dns.RcodeNameError))
				}
			})

			By("reading /api/stats (collection is async, so poll)", func() {
				Eventually(func(g Gomega) {
					res := fetchStats(ctx, g, statsURL)
					g.Expect(res.Summary.Queries).Should(BeNumerically("==", 3))
					// all three queries are attributed to the one client, none to its IP
					g.Expect(res.TopClients).Should(ConsistOf(api.ApiNameCount{Name: "ecsclient", Count: 3}))
				}, "30s", "500ms").Should(Succeed())
			})
		})
})
