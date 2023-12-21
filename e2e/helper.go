package e2e

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/docker/go-connections/nat"
	"github.com/miekg/dns"
	"github.com/onsi/ginkgo/v2"
	"github.com/testcontainers/testcontainers-go"
)

//nolint:gochecknoglobals
var (
	// currentNetwork is the global test network instance.
	currentNetwork = testNetwork{}
)

// WithNetwork attaches the container with the given alias to the test network
func WithNetwork(ctx context.Context, alias string) testcontainers.CustomizeRequestOption {
	return func(req *testcontainers.GenericContainerRequest) {
		networkName := currentNetwork.Name()
		network, err := testcontainers.GenericNetwork(ctx, testcontainers.GenericNetworkRequest{
			NetworkRequest: testcontainers.NetworkRequest{
				Name:           networkName,
				CheckDuplicate: true, // force the Docker provider to reuse an existing network
				Attachable:     true,
			},
		})

		if err != nil && !strings.Contains(err.Error(), "already exists") {
			ginkgo.Fail(fmt.Sprintf("Failed to create network '%s'. Container won't be attached to this network: %v",
				networkName, err))

			return
		}

		// decrement the network counter when the test is finished and remove the network if it is not used anymore.
		ginkgo.DeferCleanup(func(ctx context.Context) error {
			if currentNetwork.Detach() {
				if err := network.Remove(ctx); err != nil &&
					!strings.Contains(err.Error(), "removing") &&
					!strings.Contains(err.Error(), "not found") {
					return err
				}
			}

			return nil
		})

		// increment the network counter when the container is created.
		currentNetwork.Attach()

		// attaching to the network because it was created with success or it already existed.
		req.Networks = append(req.Networks, networkName)

		if req.NetworkAliases == nil {
			req.NetworkAliases = make(map[string][]string)
		}

		req.NetworkAliases[networkName] = []string{alias}
	}
}

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
) (testcontainers.Container, error) {
	greq := testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	}
	WithNetwork(ctx, alias).Customize(&greq)

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
