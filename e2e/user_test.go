package e2e

import (
	"context"

	"github.com/moby/moby/api/types/container"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/testcontainers/testcontainers-go"
)

var _ = Describe("Container user", func() {
	var e2eNet *testcontainers.DockerNetwork

	BeforeEach(func(ctx context.Context) {
		e2eNet = getRandomNetwork(ctx)
	})

	DescribeTable("starts and passes healthcheck",
		func(ctx context.Context, user string) {
			req := buildBlockyContainerRequest(createTempFile(dedent(`
				upstreams:
				  groups:
				    default:
				      - 127.0.0.1
				`)))

			baseConfigModifier := req.ConfigModifier
			req.ConfigModifier = func(c *container.Config) {
				baseConfigModifier(c)
				c.User = user
			}

			blocky, err := startContainerWithNetwork(ctx, req, "blocky", e2eNet)
			Expect(err).Should(Succeed())
			Expect(blocky.IsRunning()).Should(BeTrue())
		},
		Entry("named user and group", "blocky:blocky"),
		Entry("named user", "blocky"),
		Entry("numeric UID and GID", "100:100"),
	)
})
