package e2e

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/0xERR0R/blocky/helpertest"
	"github.com/0xERR0R/blocky/util"
	"github.com/avast/retry-go/v4"
	"github.com/docker/go-connections/nat"
	"github.com/miekg/dns"
	"github.com/onsi/ginkgo/v2"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

//nolint:gochecknoglobals
var NetworkName = fmt.Sprintf("blocky-e2e-network_%d", time.Now().Unix())

const (
	redisImage        = "redis:7"
	postgresImage     = "postgres:15"
	mariaDBImage      = "mariadb:10"
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

func createRedisContainer() (testcontainers.Container, error) {
	ctx := context.Background()

	req := testcontainers.ContainerRequest{
		Image:          redisImage,
		Networks:       []string{NetworkName},
		ExposedPorts:   []string{"6379/tcp"},
		NetworkAliases: map[string][]string{NetworkName: {"redis"}},
		WaitingFor:     wait.ForExposedPort(),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})

	return container, err
}

func createPostgresContainer() (testcontainers.Container, error) {
	ctx := context.Background()

	req := testcontainers.ContainerRequest{
		Image:          postgresImage,
		Networks:       []string{NetworkName},
		ExposedPorts:   []string{"5432/tcp"},
		NetworkAliases: map[string][]string{NetworkName: {"postgres"}},
		Env: map[string]string{
			"POSTGRES_USER":     "user",
			"POSTGRES_PASSWORD": "user",
		},
		WaitingFor: wait.ForExposedPort(),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})

	return container, err
}

func createMariaDBContainer() (testcontainers.Container, error) {
	ctx := context.Background()

	req := testcontainers.ContainerRequest{
		Image:          mariaDBImage,
		Networks:       []string{NetworkName},
		ExposedPorts:   []string{"3306/tcp"},
		NetworkAliases: map[string][]string{NetworkName: {"mariaDB"}},
		Env: map[string]string{
			"MARIADB_USER":          "user",
			"MARIADB_PASSWORD":      "user",
			"MARIADB_DATABASE":      "user",
			"MARIADB_ROOT_PASSWORD": "user",
		},
		WaitingFor: wait.ForAll(wait.ForLog("ready for connections"), wait.ForExposedPort()),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})

	return container, err
}

func createBlockyContainer(tmpDir *helpertest.TmpFolder, lines ...string) (testcontainers.Container, error) {
	f1 := tmpDir.CreateStringFile("config1.yaml",
		lines...,
	)
	if f1.Error != nil {
		return nil, f1.Error
	}

	const modeOwner = 700

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
		// can't use forExposedPorts / forListeningPorts because it needs "/bin/sh" in container
		WaitingFor: wait.NewExecStrategy([]string{"/app/blocky", "healthcheck"}),
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
	}

	// check if DNS interface is working.
	// Sometimes the internal health check returns OK, but the container port is not mapped yet
	const retryAttempts = 3
	err = retry.Do(
		func() error {
			_, err = doDNSRequest(container, util.NewMsgWithQuestion("healthcheck.blocky.", dns.Type(dns.TypeA)))

			return err
		},
		retry.Attempts(retryAttempts),
		retry.DelayType(retry.BackOffDelay),
		retry.Delay(time.Second))

	if err != nil {
		return container, fmt.Errorf("can't perform the healthcheck request: %w", err)
	}

	return container, err
}

func doDNSRequest(blocky testcontainers.Container, message *dns.Msg) (*dns.Msg, error) {
	const timeout = 5 * time.Second

	c := &dns.Client{
		Net:     "tcp",
		Timeout: timeout,
	}

	host, port, err := getContainerHostPort(blocky, "53/tcp")
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
