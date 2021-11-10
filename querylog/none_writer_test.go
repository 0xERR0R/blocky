package querylog

import (
	. "github.com/onsi/ginkgo"
)

var _ = Describe("NoneWriter", func() {

	Describe("NoneWriter", func() {
		When("write is called", func() {
			It("should do nothing", func() {
				NewNoneWriter().Write(nil)
			})
		})
		When("cleanUp is called", func() {
			It("should do nothing", func() {
				NewNoneWriter().CleanUp()
			})
		})
	})

})
