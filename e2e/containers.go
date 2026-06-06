package e2e

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/util"
	"github.com/avast/retry-go/v4"
	"github.com/miekg/dns"
	"github.com/moby/moby/api/types/container"
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
	timescaleImage    = "timescale/timescaledb:latest-pg15"
	mariaDBImage      = "mariadb:11"
	mokaImage         = "ghcr.io/0xerr0r/dns-mokka:0.4.0"
	staticServerImage = "halverneus/static-file-server:latest"
	blockyImage       = "blocky-e2e"
)

// helper constants
const (
	// modeWorldReadable is used for files mounted into the blocky container: blocky
	// runs as a non-root user (see Dockerfile `USER 100`) that doesn't own the
	// copied files, so it can only read them via the world-readable bit.
	modeWorldReadable = 0o444
	// modeWorldReadableDir is used for host directories bind-mounted into containers,
	// so a container user with a different UID can traverse and read them.
	modeWorldReadableDir = 0o755
	startupTimeout       = 30 * time.Second

	// healthcheckStartInterval overrides Docker's 5s default start-interval so
	// blocky (ready in <1s) is probed and marked healthy almost immediately.
	healthcheckStartInterval = 250 * time.Millisecond
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
//
// The file is served via a bind-mounted host directory so that the host file's
// modification time is visible inside the container. This allows Go's
// http.FileServer (used by halverneus/static-file-server) to emit a valid
// Last-Modified header and return 304 for conditional requests.
func createHTTPServerContainer(ctx context.Context, alias string, e2eNet *testcontainers.DockerNetwork,
	filename string, lines ...string,
) (testcontainers.Container, error) {
	dir, err := os.MkdirTemp("", "blocky_e2e_httpdir-")
	Expect(err).Should(Succeed())
	Expect(os.Chmod(dir, modeWorldReadableDir)).Should(Succeed()) // container user (different UID) must traverse/read the bind mount
	DeferCleanup(func() error {
		return os.RemoveAll(dir)
	})

	f, err := os.OpenFile(filepath.Join(dir, filename), os.O_CREATE|os.O_WRONLY, modeWorldReadable)
	Expect(err).Should(Succeed())
	for i, l := range lines {
		if i != 0 {
			_, err = f.WriteString("\n")
			Expect(err).Should(Succeed())
		}
		_, err = f.WriteString(l)
		Expect(err).Should(Succeed())
	}
	Expect(f.Close()).Should(Succeed())

	req := testcontainers.ContainerRequest{
		Image:        staticServerImage,
		ExposedPorts: []string{"8080/tcp"},
		Env:          map[string]string{"FOLDER": "/data"},
		HostConfigModifier: func(hc *container.HostConfig) {
			hc.Binds = append(hc.Binds, dir+":/data:ro")
		},
	}

	return startContainerWithNetwork(ctx, req, alias, e2eNet)
}

// createRedisContainer creates a redis container attached to the test network under the alias 'redis'.
// It is automatically terminated when the test is finished.
func createRedisContainer(ctx context.Context, e2eNet *testcontainers.DockerNetwork,
) (*redis.RedisContainer, error) {
	return deferTerminate(redis.Run(ctx,
		redisImage,
		redis.WithLogLevel(redis.LogLevelVerbose),
		withNetwork("redis", e2eNet),
	))
}

// createRedisContainerWithUnixSocket creates a redis container that listens only on a unix socket
// (no TCP) attached to the test network under the alias 'redis'. The socket is created at
// containerSocketDir+"/redis.sock" inside a directory that is bind-mounted from hostSocketDir, so both
// the blocky container and the host can connect to redis purely via the socket.
// It is automatically terminated when the test is finished.
func createRedisContainerWithUnixSocket(ctx context.Context, e2eNet *testcontainers.DockerNetwork,
	hostSocketDir, containerSocketDir string,
) (testcontainers.Container, error) {
	socketPath := containerSocketDir + "/redis.sock"

	req := testcontainers.ContainerRequest{
		Image: redisImage,
		// Disable TCP (port 0) so the socket is the only way in; 777 lets the (non-root) blocky
		// container connect to the socket created by the (root) redis process.
		Cmd:        []string{"redis-server", "--port", "0", "--unixsocket", socketPath, "--unixsocketperm", "777"},
		WaitingFor: wait.ForLog("Ready to accept connections unix"),
		HostConfigModifier: func(hc *container.HostConfig) {
			hc.Binds = append(hc.Binds, hostSocketDir+":"+containerSocketDir)
		},
	}

	return startContainerWithNetwork(ctx, req, "redis", e2eNet)
}

// redisTestPassword is the password required by createRedisContainerWithPassword.
const redisTestPassword = "e2e-redis-secret" //nolint:gosec // test-only password for the e2e redis container

// createRedisContainerWithPassword creates a redis container that requires authentication,
// attached to the test network under the alias 'redis'.
// It is automatically terminated when the test is finished.
func createRedisContainerWithPassword(ctx context.Context, e2eNet *testcontainers.DockerNetwork,
) (*redis.RedisContainer, error) {
	return deferTerminate(redis.Run(ctx,
		redisImage,
		testcontainers.WithCmd("redis-server", "--requirepass", redisTestPassword, "--loglevel", "verbose"),
		withNetwork("redis", e2eNet),
	))
}

// createPostgresContainer creates a postgres container attached to the test network under the alias 'postgres'.
// It creates a database 'user' with user 'user' and password 'user'.
// It is automatically terminated when the test is finished.
func createPostgresContainer(ctx context.Context, e2eNet *testcontainers.DockerNetwork,
) (*postgres.PostgresContainer, error) {
	const waitLogOccurrence = 2

	return deferTerminate(postgres.Run(ctx,
		postgresImage,

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

// createTimescaleContainer creates a postgres container with timescale extension attached to the test network under the
// alias 'timescale'. It creates a database 'user' with user 'user' and password 'user'.
// It is automatically terminated when the test is finished.
func createTimescaleContainer(ctx context.Context, e2eNet *testcontainers.DockerNetwork,
) (*postgres.PostgresContainer, error) {
	const waitLogOccurrence = 2

	return deferTerminate(postgres.Run(ctx,
		timescaleImage,

		postgres.WithDatabase("user"),
		postgres.WithUsername("user"),
		postgres.WithPassword("user"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(waitLogOccurrence).
				WithStartupTimeout(startupTimeout)),
		withNetwork("timescale", e2eNet),
	))
}

// createMariaDBContainer creates a mariadb container attached to the test network under the alias 'mariaDB'.
// It creates a database 'user' with user 'user' and password 'user'.
// It is automatically terminated when the test is finished.
func createMariaDBContainer(ctx context.Context, e2eNet *testcontainers.DockerNetwork,
) (*mariadb.MariaDBContainer, error) {
	return deferTerminate(mariadb.Run(ctx,
		mariaDBImage,
		mariadb.WithDatabase("user"),
		mariadb.WithUsername("user"),
		mariadb.WithPassword("user"),
		withNetwork("mariaDB", e2eNet),
	))
}

// buildBlockyContainerRequest builds a container request for blocky with the given config file.
func buildBlockyContainerRequest(confFile string) testcontainers.ContainerRequest {
	coverDir := os.Getenv("GOCOVERDIR")
	image := blockyImage
	if coverImageOverride := os.Getenv("BLOCKY_IMAGE"); coverImageOverride != "" {
		image = coverImageOverride
	}

	req := testcontainers.ContainerRequest{
		Image:        image,
		ExposedPorts: []string{"53/tcp", "53/udp", "4000/tcp", "4000/udp"},
		Files: []testcontainers.ContainerFile{
			{
				HostFilePath:      confFile,
				ContainerFilePath: "/app/config.yml",
				FileMode:          modeWorldReadable,
			},
		},
		ConfigModifier: func(c *container.Config) {
			c.Healthcheck = &container.HealthConfig{
				Interval: time.Second,
				// During the image's start period Docker probes at the
				// start-interval, which defaults to 5s. blocky is ready in
				// <1s, so without this every container wastes ~5s waiting to
				// be marked healthy.
				StartInterval: healthcheckStartInterval,
			}
			// Enable coverage collection if GOCOVERDIR is set
			if coverDir != "" {
				c.Env = append(c.Env, "GOCOVERDIR=/tmp/coverage")
			}
		},
		HostConfigModifier: func(hc *container.HostConfig) {
			// Mount coverage directory if enabled
			if coverDir != "" {
				hc.Binds = append(hc.Binds, coverDir+":/tmp/coverage")
			}
		},
		WaitingFor: wait.ForHealthCheck().WithStartupTimeout(startupTimeout),
	}

	return req
}

// createBlockyContainerInternal builds and starts a blocky container from the given config
// lines, mounting any extraFiles in addition to the generated config.yml and adding any
// Docker bind mounts (each in "hostPath:containerPath" form).
func createBlockyContainerInternal(ctx context.Context, e2eNet *testcontainers.DockerNetwork,
	extraFiles []testcontainers.ContainerFile, binds []string, lines ...string,
) (testcontainers.Container, error) {
	// Add timeout to context
	ctx, cancel := context.WithTimeout(ctx, 2*startupTimeout)
	defer cancel()

	confFile := createTempFile(lines...)

	cfg, err := config.LoadConfig(confFile, true)
	if err != nil {
		return nil, fmt.Errorf("can't create config struct %w", err)
	}

	req := buildBlockyContainerRequest(confFile)
	req.Files = append(req.Files, extraFiles...)

	if len(binds) > 0 {
		baseHostConfigModifier := req.HostConfigModifier
		req.HostConfigModifier = func(hc *container.HostConfig) {
			baseHostConfigModifier(hc)
			hc.Binds = append(hc.Binds, binds...)
		}
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

// createBlockyContainerWithBinds creates a blocky container like createBlockyContainer, but additionally
// mounts the given Docker bind mounts (each in "hostPath:containerPath" form) into the container.
// It is automatically terminated when the test is finished.
func createBlockyContainerWithBinds(ctx context.Context, e2eNet *testcontainers.DockerNetwork,
	binds []string, lines ...string,
) (testcontainers.Container, error) {
	return createBlockyContainerInternal(ctx, e2eNet, nil, binds, lines...)
}

// createBlockyContainer creates a blocky container with a config provided by the given lines.
// It is attached to the test network under the alias 'blocky'.
// It is automatically terminated when the test is finished.
func createBlockyContainer(ctx context.Context, e2eNet *testcontainers.DockerNetwork,
	lines ...string,
) (testcontainers.Container, error) {
	return createBlockyContainerInternal(ctx, e2eNet, nil, nil, lines...)
}

// createBlockyContainerFromString creates a blocky container with a config provided as a single YAML string.
// It is attached to the test network under the alias 'blocky'.
// It is automatically terminated when the test is finished.
func createBlockyContainerFromString(ctx context.Context, e2eNet *testcontainers.DockerNetwork,
	configYAML string,
) (testcontainers.Container, error) {
	return createBlockyContainer(ctx, e2eNet, strings.Split(configYAML, "\n")...)
}

// createBlockyContainerWithFiles is like createBlockyContainerFromString but also
// mounts each given host file into the container at the SAME absolute path, so a
// config `file:` reference resolves both during the host-side LoadConfig pre-flight
// and inside the container.
func createBlockyContainerWithFiles(ctx context.Context, e2eNet *testcontainers.DockerNetwork,
	hostFiles []string, configYAML string,
) (testcontainers.Container, error) {
	files := make([]testcontainers.ContainerFile, 0, len(hostFiles))
	for _, f := range hostFiles {
		files = append(files, testcontainers.ContainerFile{
			HostFilePath:      f,
			ContainerFilePath: f,
			FileMode:          modeWorldReadable, // world-readable so the container user can read it
		})
	}

	return createBlockyContainerInternal(ctx, e2eNet, files, nil, strings.Split(configYAML, "\n")...)
}

func checkBlockyReadiness(ctx context.Context, cfg *config.Config, container testcontainers.Container) error {
	var err error

	const retryAttempts = 3

	err = retry.Do(
		func() error {
			_, err = doDNSRequest(ctx, container, util.NewMsgWithQuestion("healthcheck.blocky.", dns.Type(dns.TypeA)))
			if err != nil {
				return fmt.Errorf("DNS request failed: %w", err)
			}

			return nil
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
	host, port, err := getContainerHostPort(ctx, container, containerPort+"/tcp")
	if err != nil {
		return err
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"http://"+net.JoinHostPort(host, port), nil)
	if err != nil {
		return err
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("received not OK status: %d", resp.StatusCode)
	}

	return nil
}

// createBlockyContainerWithCapDrop creates a blocky container that listens on
// the given DNS port with ALL Linux capabilities dropped. It verifies the image
// execs and serves DNS under a PSS-Restricted-style runtime (Kubernetes
// Restricted profile / docker --cap-drop ALL). It builds on the standard blocky
// container request, overriding only the exposed ports, the healthcheck target
// port, and the dropped capabilities — so image resolution and coverage wiring
// are inherited.
func createBlockyContainerWithCapDrop(ctx context.Context, e2eNet *testcontainers.DockerNetwork,
	dnsPort int, lines ...string,
) (testcontainers.Container, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*startupTimeout)
	defer cancel()

	confFile := createTempFile(lines...)
	portStr := strconv.Itoa(dnsPort)

	req := buildBlockyContainerRequest(confFile)
	req.ExposedPorts = []string{portStr + "/tcp", portStr + "/udp"}

	baseConfigModifier := req.ConfigModifier
	req.ConfigModifier = func(c *container.Config) {
		baseConfigModifier(c)
		// Point the healthcheck at the configured DNS port (the image default is 53).
		c.Healthcheck.Test = []string{"CMD", "/app/blocky", "healthcheck", "-p", portStr}
	}

	baseHostConfigModifier := req.HostConfigModifier
	req.HostConfigModifier = func(hc *container.HostConfig) {
		baseHostConfigModifier(hc)
		hc.CapDrop = []string{"ALL"}
	}

	return startContainerWithNetwork(ctx, req, "blocky", e2eNet)
}

// createTempFile creates a temporary file with the given lines which is deleted after the test
// Each created file is prefixed with 'blocky_e2e_file-'
func createTempFile(lines ...string) string {
	file, err := os.CreateTemp("", "blocky_e2e_file-")
	Expect(err).Should(Succeed())

	defer file.Close()

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
