package parsers

import (
	"bufio"
	"context"
	"io"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Lines", func() {
	var (
		data string

		sutReader io.Reader
		sut       SeriesParser[string]
	)

	BeforeEach(func() {
		sutReader = nil
	})

	JustBeforeEach(func() {
		if sutReader == nil {
			sutReader = strings.NewReader(data)
		}

		sut = Lines(sutReader)
	})

	When("it has normal lines", func() {
		BeforeEach(func() {
			sutReader = linesReader(
				"first",
				"second",
				"third",
			)
		})

		It("returns them all", func() {
			str, err := sut.Next(context.Background())
			Expect(err).Should(Succeed())
			Expect(str).Should(Equal("first"))
			Expect(sut.Position()).Should(Equal("line 1"))

			str, err = sut.Next(context.Background())
			Expect(err).Should(Succeed())
			Expect(str).Should(Equal("second"))
			Expect(sut.Position()).Should(Equal("line 2"))

			str, err = sut.Next(context.Background())
			Expect(err).Should(Succeed())
			Expect(str).Should(Equal("third"))
			Expect(sut.Position()).Should(Equal("line 3"))

			_, err = sut.Next(context.Background())
			Expect(err).ShouldNot(Succeed())
			Expect(err).Should(MatchError(io.EOF))
			Expect(IsNonResumableErr(err)).Should(BeTrue())
			Expect(sut.Position()).Should(Equal("line 4"))
		})
	})

	When("it has empty lines", func() {
		BeforeEach(func() {
			sutReader = linesReader(
				"",
				"  ",
				"\t",
				"\r",
			)
		})

		It("skips them", func() {
			_, err := sut.Next(context.Background())
			Expect(err).ShouldNot(Succeed())
			Expect(err).Should(MatchError(io.EOF))
			Expect(IsNonResumableErr(err)).Should(BeTrue())
			Expect(sut.Position()).Should(Equal("line 5"))
		})
	})

	When("it has commented lines", func() {
		BeforeEach(func() {
			sutReader = linesReader(
				"first",
				"# comment 1",
				"# comment 2",
				"second",
			)
		})

		It("returns them all", func() {
			str, err := sut.Next(context.Background())
			Expect(err).Should(Succeed())
			Expect(str).Should(Equal("first"))
			Expect(sut.Position()).Should(Equal("line 1"))

			str, err = sut.Next(context.Background())
			Expect(err).Should(Succeed())
			Expect(str).Should(Equal("second"))
			Expect(sut.Position()).Should(Equal("line 4"))
		})
	})

	When("it has end of line comments", func() {
		BeforeEach(func() {
			sutReader = linesReader(
				"first# comment",
				"second # other",
			)
		})

		It("returns them all", func() {
			str, err := sut.Next(context.Background())
			Expect(err).Should(Succeed())
			Expect(str).Should(Equal("first"))
			Expect(sut.Position()).Should(Equal("line 1"))

			str, err = sut.Next(context.Background())
			Expect(err).Should(Succeed())
			Expect(str).Should(Equal("second"))
			Expect(sut.Position()).Should(Equal("line 2"))
		})
	})

	When("there's a scan error", func() {
		BeforeEach(func() {
			sutReader = linesReader(
				"too long " + strings.Repeat(".", bufio.MaxScanTokenSize),
			)
		})

		It("fails", func() {
			_, err := sut.Next(context.Background())
			Expect(err).ShouldNot(Succeed())
			Expect(sut.Position()).Should(Equal("line 1"))
		})
	})

	When("context is cancelled", func() {
		BeforeEach(func() {
			sutReader = linesReader(
				"first",
				"second",
			)
		})

		It("stops parsing", func() {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			str, err := sut.Next(ctx)
			Expect(err).Should(Succeed())
			Expect(str).Should(Equal("first"))
			Expect(sut.Position()).Should(Equal("line 1"))

			cancel()

			_, err = sut.Next(ctx)
			Expect(err).ShouldNot(Succeed())
			Expect(IsNonResumableErr(err)).Should(BeTrue())
			Expect(sut.Position()).Should(Equal("line 2"))
		})
	})

	When("last line has no newline", func() {
		BeforeEach(func() {
			data = "first\nlast"
		})

		It("still returns it", func() {
			str, err := sut.Next(context.Background())
			Expect(err).Should(Succeed())
			Expect(str).Should(Equal("first"))
			Expect(sut.Position()).Should(Equal("line 1"))

			str, err = sut.Next(context.Background())
			Expect(err).Should(Succeed())
			Expect(str).Should(Equal("last"))
			Expect(sut.Position()).Should(Equal("line 2"))
		})
	})
})

func linesReader(lines ...string) io.Reader {
	data := strings.Join(lines, "\n") + "\n"

	return strings.NewReader(data)
}
