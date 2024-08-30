package util_test

import (
	"strings"

	. "github.com/0xERR0R/blocky/util"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Slices Util", func() {
	Describe("ConvertEach", func() {
		It("calls the converter for each element", func() {
			Expect(ConvertEach([]string{"a", "b"}, strings.ToUpper)).Should(Equal([]string{"A", "B"}))
		})

		It("maps nil to nil", func() {
			Expect(ConvertEach(nil, func(any) any {
				Fail("converter must not be called")

				return nil
			})).Should(BeNil())
		})
	})

	Describe("ConcatSlices", func() {
		It("calls the converter for each element", func() {
			Expect(ConcatSlices(
				[]string{"a", "b"},
				[]string{"c"},
				[]string{},
				[]string{"d", "e"},
			)).Should(Equal([]string{"a", "b", "c", "d", "e"}))
		})
	})
})
