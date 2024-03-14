package e2e

import (
	"bufio"
	"context"
	"net"
	"strings"
	"time"

	"github.com/docker/go-connections/nat"
	"github.com/miekg/dns"
	"github.com/onsi/ginkgo/v2"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/network"
)

// deferTerminate is a helper function to terminate the container when the test is finished.
func deferTerminate[T testcontainers.Container](container T, err error) (T, error) {
	ginkgo.DeferCleanup(func(ctx context.Context) error {
		if container.IsRunning() {
			return container.Terminate(ctx)
		}

		return nil
	})

	return container, err
}

// startContainerWithNetwork starts the container with the given alias and attaches it to the test network.
// The container is wrapped with deferTerminate to terminate the container when the test is finished.
func startContainerWithNetwork(ctx context.Context, req testcontainers.ContainerRequest, alias string,
	e2eNet *testcontainers.DockerNetwork,
) (testcontainers.Container, error) {
	greq := testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	}
	network.WithNetwork([]string{alias}, e2eNet).Customize(&greq)

	return deferTerminate(testcontainers.GenericContainer(ctx, greq))
}

// doDNSRequest sends the given DNS message to the container and returns the response.
func doDNSRequest(ctx context.Context, container testcontainers.Container, message *dns.Msg) (*dns.Msg, error) {
	const timeout = 5 * time.Second

	c := &dns.Client{
		Net:     "tcp",
		Timeout: timeout,
	}

	host, port, err := getContainerHostPort(ctx, container, "53/tcp")
	if err != nil {
		return nil, err
	}

	msg, _, err := c.Exchange(message, net.JoinHostPort(host, port))

	return msg, err
}

// getContainerHostPort returns the host and port of the given container and port.
func getContainerHostPort(ctx context.Context, c testcontainers.Container, p nat.Port) (host, port string, err error) {
	res, err := c.MappedPort(ctx, p)
	if err != nil {
		return "", "", err
	}

	host, err = c.Host(ctx)
	if err != nil {
		return "", "", err
	}

	return host, res.Port(), err
}

// getContainerLogs returns the logs of the given container.
func getContainerLogs(ctx context.Context, c testcontainers.Container) (lines []string, err error) {
	if r, err := c.Logs(ctx); err == nil {
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
