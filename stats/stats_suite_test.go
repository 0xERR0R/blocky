package stats

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/sirupsen/logrus"
)

func TestStats(t *testing.T) {
	logrus.SetLevel(logrus.WarnLevel)
	RegisterFailHandler(Fail)
	RunSpecs(t, "Stats Suite")
}
