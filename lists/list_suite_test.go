package lists

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/sirupsen/logrus"
)

func TestLists(t *testing.T) {
	logrus.SetLevel(logrus.WarnLevel)
	RegisterFailHandler(Fail)
	RunSpecs(t, "Lists Suite")
}
