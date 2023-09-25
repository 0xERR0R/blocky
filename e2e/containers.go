package e2e

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/helpertest"
	"github.com/0xERR0R/blocky/util"
	"github.com/avast/retry-go/v4"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/go-connections/nat"
	"github.com/miekg/dns"
	"github.com/onsi/ginkgo/v2"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/mariadb"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/modules/redis"
	"github.com/testcontainers/testcontainers-go/wait"
)

//nolint:gochecknoglobals
var NetworkName = fmt.Sprintf("blocky-e2e-network_%d", time.Now().Unix())

const (
	redisImage        = "redis:7"
	postgresImage     = "postgres:15.2-alpine"
	mariaDBImage      = "mariadb:11"
	mokaImage         = "ghcr.io/0xerr0r/dns-mokka:0.2.0"
	staticServerImage = "halverneus/static-file-server:latest"
	blockyImage       = "blocky-e2e"
)

func createDNSMokkaContainer(alias string, rules ...string) (testcontainers.Container, error) {
	ctx := context.Background()

	mokaRules := make(map[string]string)

	for i, rule := range rules {
		mokaRules[fmt.Sprintf("MOKKA_RULE_%d", i)] = rule
	}

	req := testcontainers.ContainerRequest{
		Image:          mokaImage,
		Networks:       []string{NetworkName},
		ExposedPorts:   []string{"53/tcp", "53/udp"},
		NetworkAliases: map[string][]string{NetworkName: {alias}},
		WaitingFor:     wait.ForExposedPort(),
		Env:            mokaRules,
	}

	return testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
}

func createHTTPServerContainer(alias string, tmpDir *helpertest.TmpFolder,
	filename string, lines ...string,
) (testcontainers.Container, error) {
	f1 := tmpDir.CreateStringFile(filename,
		lines...,
	)
	if f1.Error != nil {
		return nil, f1.Error
	}

	const modeOwner = 700

	ctx := context.Background()
	req := testcontainers.ContainerRequest{
		Image:          staticServerImage,
		Networks:       []string{NetworkName},
		NetworkAliases: map[string][]string{NetworkName: {alias}},

		ExposedPorts: []string{"8080/tcp"},
		Env:          map[string]string{"FOLDER": "/"},
		Files: []testcontainers.ContainerFile{
			{
				HostFilePath:      f1.Path,
				ContainerFilePath: fmt.Sprintf("/%s", filename),
				FileMode:          modeOwner,
			},
		},
	}

	return testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
}

func WithNetwork(network string) testcontainers.CustomizeRequestOption {
	return func(req *testcontainers.GenericContainerRequest) {
		req.NetworkAliases = map[string][]string{NetworkName: {network}}
		req.Networks = []string{NetworkName}
	}
}

func createRedisContainer() (*redis.RedisContainer, error) {
	ctx := context.Background()

	return redis.RunContainer(ctx,
		testcontainers.WithImage(redisImage),
		redis.WithLogLevel(redis.LogLevelVerbose),
		WithNetwork("redis"),
	)
}

func createPostgresContainer() (*postgres.PostgresContainer, error) {
	ctx := context.Background()

	const waitLogOccurrence = 2

	return postgres.RunContainer(ctx,
		testcontainers.WithImage(postgresImage),

		postgres.WithDatabase("user"),
		postgres.WithUsername("user"),
		postgres.WithPassword("user"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(waitLogOccurrence).
				WithStartupTimeout(startupTimeout)),
		WithNetwork("postgres"),
	)
}

func createMariaDBContainer() (*mariadb.MariaDBContainer, error) {
	ctx := context.Background()

	return mariadb.RunContainer(ctx,
		testcontainers.WithImage(mariaDBImage),
		mariadb.WithDatabase("user"),
		mariadb.WithUsername("user"),
		mariadb.WithPassword("user"),
		WithNetwork("mariaDB"),
	)
}

const (
	modeOwner      = 700
	startupTimeout = 30 * time.Second
)

func createBlockyContainer(tmpDir *helpertest.TmpFolder, lines ...string) (testcontainers.Container, error) {
	f1 := tmpDir.CreateStringFile("config1.yaml",
		lines...,
	)
	if f1.Error != nil {
		return nil, f1.Error
	}

	cfg, err := config.LoadConfig(f1.Path, true)
	if err != nil {
		return nil, fmt.Errorf("can't create config struct %w", err)
	}

	ctx := context.Background()
	req := testcontainers.ContainerRequest{
		Image:    blockyImage,
		Networks: []string{NetworkName},

		ExposedPorts: []string{"53/tcp", "53/udp", "4000/tcp"},

		Files: []testcontainers.ContainerFile{
			{
				HostFilePath:      f1.Path,
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

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		// attach container log if error occurs
		if r, err := container.Logs(context.Background()); err == nil {
			if b, err := io.ReadAll(r); err == nil {
				ginkgo.AddReportEntry("blocky container log", string(b))
			}
		}

		return container, err
	}

	// check if DNS/HTTP interface is working.
	// Sometimes the internal health check returns OK, but the container port is not mapped yet
	err = checkBlockyReadiness(cfg, container)

	if err != nil {
		return container, fmt.Errorf("container not ready: %w", err)
	}

	return container, nil
}

func checkBlockyReadiness(cfg *config.Config, container testcontainers.Container) error {
	var err error

	const retryAttempts = 3

	err = retry.Do(
		func() error {
			_, err = doDNSRequest(container, util.NewMsgWithQuestion("healthcheck.blocky.", dns.Type(dns.TypeA)))

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
				return doHTTPRequest(container, port)
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

func doHTTPRequest(container testcontainers.Container, containerPort string) error {
	host, port, err := getContainerHostPort(container, nat.Port(fmt.Sprintf("%s/tcp", containerPort)))
	if err != nil {
		return err
	}

	resp, err := http.Get(fmt.Sprintf("http://%s", net.JoinHostPort(host, port)))
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("received not OK status: %d", resp.StatusCode)
	}

	return err
}

func doDNSRequest(container testcontainers.Container, message *dns.Msg) (*dns.Msg, error) {
	const timeout = 5 * time.Second

	c := &dns.Client{
		Net:     "tcp",
		Timeout: timeout,
	}

	host, port, err := getContainerHostPort(container, "53/tcp")
	if err != nil {
		return nil, err
	}

	msg, _, err := c.Exchange(message, net.JoinHostPort(host, port))

	return msg, err
}

func getContainerHostPort(c testcontainers.Container, p nat.Port) (host, port string, err error) {
	res, err := c.MappedPort(context.Background(), p)
	if err != nil {
		return "", "", err
	}

	host, err = c.Host(context.Background())

	if err != nil {
		return "", "", err
	}

	return host, res.Port(), err
}

func getContainerLogs(c testcontainers.Container) (lines []string, err error) {
	if r, err := c.Logs(context.Background()); err == nil {
		scanner := bufio.NewScanner(r)
		for scanner.Scan() {
			line := scanner.Text()
			if len(strings.TrimSpace(line)) > 0 {
				lines = append(lines, line)
			}
		}

		if err := scanner.Err(); err != nil {
			return nil, err
		}

		return lines, nil
	}

	return nil, err
}
