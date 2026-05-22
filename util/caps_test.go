package util

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("RaiseNetBindService", func() {
	It("returns without error and is stable across calls", func() {
		// effective depends on whether CAP_NET_BIND_SERVICE is in the process's
		// permitted set (usually false in CI). We verify the contract that holds
		// regardless: no error, and a stable result across calls.
		effective, err := RaiseNetBindService()
		Expect(err).Should(Succeed())

		effectiveAgain, err := RaiseNetBindService()
		Expect(err).Should(Succeed())
		Expect(effectiveAgain).Should(Equal(effective))
	})
})
