package e2e

import (
	"context"

	. "github.com/onsi/gomega"
	"github.com/testcontainers/testcontainers-go"
)

// mokkaSpec defines a mock DNS upstream with its network alias and rules.
type mokkaSpec struct {
	alias string   // Docker network alias, used directly in YAML config (e.g., "moka1")
	rules []string // mokka query rules (e.g., `A google/NOERROR("A 1.2.3.4 123")`)
}

// testEnv holds all containers and network for a test scenario.
type testEnv struct {
	network *testcontainers.DockerNetwork
	mokkas  map[string]testcontainers.Container // keyed by alias
	blocky  testcontainers.Container
	httpSrv testcontainers.Container // nil if no HTTP server
}

// setupBlockyWithMokka creates a test network, one or more mokka DNS containers,
// and a blocky container with the given config.
// The mokka aliases (e.g., "moka1") can be referenced directly in the config YAML.
func setupBlockyWithMokka(
	ctx context.Context, mokkas []mokkaSpec, configYAML string,
) *testEnv {
	e2eNet := getRandomNetwork(ctx)

	env := &testEnv{
		network: e2eNet,
		mokkas:  make(map[string]testcontainers.Container, len(mokkas)),
	}

	for _, m := range mokkas {
		c, err := createDNSMokkaContainer(ctx, m.alias, e2eNet, m.rules...)
		Expect(err).Should(Succeed())

		env.mokkas[m.alias] = c
	}

	var err error
	env.blocky, err = createBlockyContainerFromString(ctx, e2eNet, configYAML)
	Expect(err).Should(Succeed())

	return env
}

// setupBlockyWithHTTPAndMokka creates a test network, one or more mokka DNS containers,
// an HTTP static file server serving a single file, and a blocky container.
// The httpAlias (e.g., "httpserver") is the network alias for the HTTP server.
func setupBlockyWithHTTPAndMokka(
	ctx context.Context, mokkas []mokkaSpec,
	httpAlias string, filename string, fileLines []string,
	configYAML string,
) *testEnv {
	e2eNet := getRandomNetwork(ctx)

	env := &testEnv{
		network: e2eNet,
		mokkas:  make(map[string]testcontainers.Container, len(mokkas)),
	}

	for _, m := range mokkas {
		c, err := createDNSMokkaContainer(ctx, m.alias, e2eNet, m.rules...)
		Expect(err).Should(Succeed())

		env.mokkas[m.alias] = c
	}

	var err error
	env.httpSrv, err = createHTTPServerContainer(ctx, httpAlias, e2eNet, filename, fileLines...)
	Expect(err).Should(Succeed())

	env.blocky, err = createBlockyContainerFromString(ctx, e2eNet, configYAML)
	Expect(err).Should(Succeed())

	return env
}
