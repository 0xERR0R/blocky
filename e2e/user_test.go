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

	// Users with primary GID 0 (the image default, "100" and "blocky") must still
	// be able to read a root-owned config with mode 0640, as before the named user
	// was introduced.
	DescribeTable("starts and passes healthcheck",
		func(ctx context.Context, user string, configMode int64) {
			req := buildBlockyContainerRequest(createTempFile(dedent(`
				upstreams:
				  groups:
				    default:
				      - 127.0.0.1
				`)))
			req.Files[0].FileMode = configMode

			baseConfigModifier := req.ConfigModifier
			req.ConfigModifier = func(c *container.Config) {
				baseConfigModifier(c)
				c.User = user
			}

			blocky, err := startContainerWithNetwork(ctx, req, "blocky", e2eNet)
			Expect(err).Should(Succeed())
			Expect(blocky.IsRunning()).Should(BeTrue())
		},
		Entry("default image user", "", int64(0o640)),
		Entry("numeric UID", "100", int64(0o640)),
		Entry("named user", "blocky", int64(0o640)),
		Entry("named user and group", "blocky:blocky", int64(modeWorldReadable)),
		Entry("numeric UID and GID", "100:100", int64(modeWorldReadable)),
	)
})
