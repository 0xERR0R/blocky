package e2e

import (
	"context"
	"testing"

	"github.com/0xERR0R/blocky/helpertest"

	"github.com/0xERR0R/blocky/log"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/testcontainers/testcontainers-go"
)

func TestLists(t *testing.T) {
	log.Silence()
	RegisterFailHandler(Fail)
	RunSpecs(t, "e2e Suite", Label("e2e"))
}

var (
	network testcontainers.Network
	tmpDir  *helpertest.TmpFolder
)

var _ = BeforeSuite(func() {
	var err error

	network, err = testcontainers.GenericNetwork(context.Background(), testcontainers.GenericNetworkRequest{
		NetworkRequest: testcontainers.NetworkRequest{
			Name:           NetworkName,
			CheckDuplicate: false,
			Attachable:     true,
		},
	})

	Expect(err).Should(Succeed())

	DeferCleanup(func() {
		err := network.Remove(context.Background())
		Expect(err).Should(Succeed())
	})

	tmpDir = helpertest.NewTmpFolder("config")
	Expect(tmpDir.Error).Should(Succeed())
	DeferCleanup(tmpDir.Clean)
})
