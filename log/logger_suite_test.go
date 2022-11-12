package log

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestLogger(t *testing.T) {
	Silence()
	RegisterFailHandler(Fail)
	RunSpecs(t, "Logger Suite")
}
