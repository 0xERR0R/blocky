package configstore

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestConfigStore(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "ConfigStore Suite")
}
