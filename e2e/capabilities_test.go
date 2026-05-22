package e2e

import (
	"context"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/testcontainers/testcontainers-go"
)

// capDropDNSPort is an unprivileged (>= 1024) DNS port used to prove the image
// runs under --cap-drop ALL without needing NET_BIND_SERVICE.
const capDropDNSPort = 1053

var _ = Describe("Restricted capabilities", Label("e2e"), func() {
	var (
		e2eNet *testcontainers.DockerNetwork
		blocky testcontainers.Container
		err    error
	)

	BeforeEach(func(ctx context.Context) {
		e2eNet = getRandomNetwork(ctx)

		_, err = createDNSMokkaContainer(ctx, "moka1", e2eNet, `A google/NOERROR("A 1.2.3.4 123")`)
		Expect(err).Should(Succeed())
	})

	Context("with all capabilities dropped on a high port", func() {
		BeforeEach(func(ctx context.Context) {
			blocky, err = createBlockyContainerWithCapDrop(ctx, e2eNet, capDropDNSPort, dedent(fmt.Sprintf(`
				upstreams:
				  groups:
				    default:
				      - moka1
				ports:
				  dns: %d
				`, capDropDNSPort)))
			Expect(err).Should(Succeed())
		})

		It("execs and serves DNS without NET_BIND_SERVICE", func(ctx context.Context) {
			Expect(blocky.IsRunning()).Should(BeTrue())
			Expect(getContainerLogs(ctx, blocky)).
				ShouldNot(ContainElement(ContainSubstring("operation not permitted")))
		})
	})
})
