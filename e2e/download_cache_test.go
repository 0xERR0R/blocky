package e2e

import (
	"context"
	"net"
	"net/http"
	"os"
	"strings"

	. "github.com/0xERR0R/blocky/helpertest"
	"github.com/0xERR0R/blocky/util"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/testcontainers/testcontainers-go"
)

var _ = Describe("Download cache", func() {
	var (
		e2eNet   *testcontainers.DockerNetwork
		blocky   testcontainers.Container
		cacheDir string
		err      error
	)

	BeforeEach(func(ctx context.Context) {
		e2eNet = getRandomNetwork(ctx)

		_, err = createDNSMokkaContainer(ctx, "moka", e2eNet, `A google/NOERROR("A 1.2.3.4 123")`)
		Expect(err).Should(Succeed())

		cacheDir, err = os.MkdirTemp("", "blocky-cache-")
		Expect(err).Should(Succeed())
		Expect(os.Chmod(cacheDir, 0o777)).Should(Succeed()) // non-root container user must write here
		DeferCleanup(func() { _ = os.RemoveAll(cacheDir) })
	})

	Context("with cachePath configured", func() {
		BeforeEach(func(ctx context.Context) {
			_, err = createHTTPServerContainer(ctx, "httpserver", e2eNet, "list.txt", "blockeddomain.com")
			Expect(err).Should(Succeed())

			blocky, err = createBlockyContainerWithBinds(ctx, e2eNet, []string{cacheDir + ":/cache"},
				strings.Split(dedent(`
					log:
					  level: debug
					upstreams:
					  groups:
					    default:
					      - moka
					ports:
					  http: 4000
					blocking:
					  loading:
					    downloads:
					      cachePath: /cache
					  denylists:
					    ads:
					      - http://httpserver:8080/list.txt
					  clientGroupsBlock:
					    default:
					      - ads
				`), "\n")...)
			Expect(err).Should(Succeed())
		})

		It("caches the body to disk and revalidates with a 304 on refresh", func(ctx context.Context) {
			By("blocking the domain after initial load", func() {
				msg := util.NewMsgWithQuestion("blockeddomain.com.", A)
				Expect(doDNSRequest(ctx, blocky, msg)).Should(BeDNSRecord("blockeddomain.com.", A, "0.0.0.0"))
			})

			By("writing exactly one cache file to the bind dir", func() {
				entries, rerr := os.ReadDir(cacheDir)
				Expect(rerr).Should(Succeed())
				Expect(entries).Should(HaveLen(1))
			})

			By("revalidating with a 304 on refresh", func() {
				host, port, gerr := getContainerHostPort(ctx, blocky, "4000/tcp")
				Expect(gerr).Should(Succeed())

				resp, perr := http.Post("http://"+net.JoinHostPort(host, port)+"/api/lists/refresh", "application/json", nil)
				Expect(perr).Should(Succeed())
				defer resp.Body.Close()
				Expect(resp.StatusCode).Should(Equal(http.StatusOK))

				Eventually(func() ([]string, error) { return getContainerLogs(ctx, blocky) }, "5s", "200ms").
					Should(ContainElement(ContainSubstring("source not modified, using cached copy")))
			})

			By("still blocking after refresh", func() {
				msg := util.NewMsgWithQuestion("blockeddomain.com.", A)
				Expect(doDNSRequest(ctx, blocky, msg)).Should(BeDNSRecord("blockeddomain.com.", A, "0.0.0.0"))
			})
		})
	})
})
