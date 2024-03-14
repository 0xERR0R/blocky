package e2e

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/util"
	"github.com/avast/retry-go/v4"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/go-connections/nat"
	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/mariadb"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/modules/redis"
	"github.com/testcontainers/testcontainers-go/wait"
)

// container image names
const (
	redisImage        = "redis:7"
	postgresImage     = "postgres:15.2-alpine"
	mariaDBImage      = "mariadb:11"
	mokaImage         = "ghcr.io/0xerr0r/dns-mokka:0.2.0"
	staticServerImage = "halverneus/static-file-server:latest"
	blockyImage       = "blocky-e2e"
)

// helper constants
const (
	modeOwner      = 700
	startupTimeout = 30 * time.Second
)

// createDNSMokkaContainer creates a DNS mokka container with the given rules attached to the test network
// under the given alias.
// It is automatically terminated when the test is finished.
func createDNSMokkaContainer(ctx context.Context, alias string, e2eNet *testcontainers.DockerNetwork,
	rules ...string,
) (testcontainers.Container, error) {
	mokaRules := make(map[string]string)

	for i, rule := range rules {
		mokaRules[fmt.Sprintf("MOKKA_RULE_%d", i)] = rule
	}

	req := testcontainers.ContainerRequest{
		Image:        mokaImage,
		ExposedPorts: []string{"53/tcp", "53/udp"},
		WaitingFor:   wait.ForExposedPort(),
		Env:          mokaRules,
	}

	return startContainerWithNetwork(ctx, req, alias, e2eNet)
}

// createHTTPServerContainer creates a static HTTP server container that serves one file with the given lines
// and is attached to the test network under the given alias.
// It is automatically terminated when the test is finished.
func createHTTPServerContainer(ctx context.Context, alias string, e2eNet *testcontainers.DockerNetwork,
	filename string, lines ...string,
) (testcontainers.Container, error) {
	file := createTempFile(lines...)

	req := testcontainers.ContainerRequest{
		Image: staticServerImage,

		ExposedPorts: []string{"8080/tcp"},
		Env:          map[string]string{"FOLDER": "/"},
		Files: []testcontainers.ContainerFile{
			{
				HostFilePath:      file,
				ContainerFilePath: fmt.Sprintf("/%s", filename),
				FileMode:          modeOwner,
			},
		},
	}

	return startContainerWithNetwork(ctx, req, alias, e2eNet)
}

// createRedisContainer creates a redis container attached to the test network under the alias 'redis'.
// It is automatically terminated when the test is finished.
func createRedisContainer(ctx context.Context, e2eNet *testcontainers.DockerNetwork,
) (*redis.RedisContainer, error) {
	return deferTerminate(redis.RunContainer(ctx,
		testcontainers.WithImage(redisImage),
		redis.WithLogLevel(redis.LogLevelVerbose),
		withNetwork("redis", e2eNet),
	))
}

// createPostgresContainer creates a postgres container attached to the test network under the alias 'postgres'.
// It creates a database 'user' with user 'user' and password 'user'.
// It is automatically terminated when the test is finished.
func createPostgresContainer(ctx context.Context, e2eNet *testcontainers.DockerNetwork,
) (*postgres.PostgresContainer, error) {
	const waitLogOccurrence = 2

	return deferTerminate(postgres.RunContainer(ctx,
		testcontainers.WithImage(postgresImage),

		postgres.WithDatabase("user"),
		postgres.WithUsername("user"),
		postgres.WithPassword("user"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(waitLogOccurrence).
				WithStartupTimeout(startupTimeout)),
		withNetwork("postgres", e2eNet),
	))
}

// createMariaDBContainer creates a mariadb container attached to the test network under the alias 'mariaDB'.
// It creates a database 'user' with user 'user' and password 'user'.
// It is automatically terminated when the test is finished.
func createMariaDBContainer(ctx context.Context, e2eNet *testcontainers.DockerNetwork,
) (*mariadb.MariaDBContainer, error) {
	return deferTerminate(mariadb.RunContainer(ctx,
		testcontainers.WithImage(mariaDBImage),
		mariadb.WithDatabase("user"),
		mariadb.WithUsername("user"),
		mariadb.WithPassword("user"),
		withNetwork("mariaDB", e2eNet),
	))
}

// createBlockyContainer creates a blocky container with a config provided by the given lines.
// It is attached to the test network under the alias 'blocky'.
// It is automatically terminated when the test is finished.
func createBlockyContainer(ctx context.Context, e2eNet *testcontainers.DockerNetwork,
	lines ...string,
) (testcontainers.Container, error) {
	confFile := createTempFile(lines...)

	cfg, err := config.LoadConfig(confFile, true)
	if err != nil {
		return nil, fmt.Errorf("can't create config struct %w", err)
	}

	req := testcontainers.ContainerRequest{
		Image: blockyImage,

		ExposedPorts: []string{"53/tcp", "53/udp", "4000/tcp"},

		Files: []testcontainers.ContainerFile{
			{
				HostFilePath:      confFile,
				ContainerFilePath: "/app/config.yml",
				FileMode:          modeOwner,
			},
		},
		ConfigModifier: func(c *container.Config) {
			c.Healthcheck = &container.HealthConfig{
				Interval: time.Second,
			}
		},
		WaitingFor: wait.ForHealthCheck().WithStartupTimeout(startupTimeout),
	}

	container, err := startContainerWithNetwork(ctx, req, "blocky", e2eNet)
	if err != nil {
		// attach container log if error occurs
		if r, err := container.Logs(ctx); err == nil {
			if b, err := io.ReadAll(r); err == nil {
				AddReportEntry("blocky container log", string(b))
			}
		}

		return container, err
	}

	// check if DNS/HTTP interface is working.
	// Sometimes the internal health check returns OK, but the container port is not mapped yet
	err = checkBlockyReadiness(ctx, cfg, container)
	if err != nil {
		return container, fmt.Errorf("container not ready: %w", err)
	}

	return container, nil
}

func checkBlockyReadiness(ctx context.Context, cfg *config.Config, container testcontainers.Container) error {
	var err error

	const retryAttempts = 3

	err = retry.Do(
		func() error {
			_, err = doDNSRequest(ctx, container, util.NewMsgWithQuestion("healthcheck.blocky.", dns.Type(dns.TypeA)))

			return err
		},
		retry.OnRetry(func(n uint, err error) {
			log.Infof("Performing retry DNS request #%d: %s\n", n, err)
		}),
		retry.Attempts(retryAttempts),
		retry.DelayType(retry.BackOffDelay),
		retry.Delay(time.Second))
	if err != nil {
		return fmt.Errorf("can't perform the DNS healthcheck request: %w", err)
	}

	for _, httpPort := range cfg.Ports.HTTP {
		parts := strings.Split(httpPort, ":")
		port := parts[len(parts)-1]

		err = retry.Do(
			func() error {
				return doHTTPRequest(ctx, container, port)
			},
			retry.OnRetry(func(n uint, err error) {
				log.Infof("Performing retry HTTP request #%d: %s\n", n, err)
			}),
			retry.Attempts(retryAttempts),
			retry.DelayType(retry.BackOffDelay),
			retry.Delay(time.Second))
		if err != nil {
			return fmt.Errorf("can't perform the HTTP request: %w", err)
		}
	}

	return nil
}

func doHTTPRequest(ctx context.Context, container testcontainers.Container, containerPort string) error {
	host, port, err := getContainerHostPort(ctx, container, nat.Port(fmt.Sprintf("%s/tcp", containerPort)))
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		fmt.Sprintf("http://%s", net.JoinHostPort(host, port)), nil)
	if err != nil {
		return err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("received not OK status: %d", resp.StatusCode)
	}

	return err
}

// createTempFile creates a temporary file with the given lines which is deleted after the test
// Each created file is prefixed with 'blocky_e2e_file-'
func createTempFile(lines ...string) string {
	file, err := os.CreateTemp("", "blocky_e2e_file-")
	Expect(err).Should(Succeed())

	DeferCleanup(func() error {
		return os.Remove(file.Name())
	})

	for i, l := range lines {
		if i != 0 {
			_, err := file.WriteString("\n")
			Expect(err).Should(Succeed())
		}

		_, err := file.WriteString(l)
		Expect(err).Should(Succeed())
	}

	return file.Name()
}
