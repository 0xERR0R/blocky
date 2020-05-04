package resolver_test

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
)

func TestResolver(t *testing.T) {
	logrus.SetLevel(logrus.WarnLevel)
	RegisterFailHandler(Fail)
	RunSpecs(t, "Resolver Suite")
}
