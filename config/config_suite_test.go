package config

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/sirupsen/logrus"
)

func TestConfig(t *testing.T) {
	logrus.SetLevel(logrus.WarnLevel)
	RegisterFailHandler(Fail)
	RunSpecs(t, "Config Suite")
}
