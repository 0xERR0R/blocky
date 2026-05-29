package evt_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestEvt(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Evt Suite")
}
