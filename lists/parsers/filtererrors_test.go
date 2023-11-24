package parsers

import (
	"context"
	"errors"
	"io"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("errorFilter", func() {
	Describe("AllowErrors", func() {
		var parser SeriesParser[struct{}]

		BeforeEach(func() {
			parser = newMockParser(func(res chan<- struct{}, err chan<- error) {
				res <- struct{}{}
				err <- errors.New("fail")
				res <- struct{}{}
				err <- errors.New("fail")
				res <- struct{}{}
				err <- errors.New("fail")
				err <- NewNonResumableError(io.EOF)
			})
		})

		When("0 errors are allowed", func() {
			It("should fail on first error", func() {
				parser = AllowErrors(parser, 0)

				_, err := parser.Next(context.Background())
				Expect(err).Should(Succeed())
				Expect(parser.Position()).Should(Equal("call 1"))

				_, err = parser.Next(context.Background())
				Expect(err).Should(HaveOccurred())
				Expect(err).Should(MatchError(ErrTooManyErrors))
				Expect(parser.Position()).Should(Equal("call 2"))
			})
		})

		When("1 error is allowed", func() {
			It("should fail on second error", func() {
				parser = AllowErrors(parser, 1)

				_, err := parser.Next(context.Background())
				Expect(err).Should(Succeed())
				Expect(parser.Position()).Should(Equal("call 1"))

				_, err = parser.Next(context.Background())
				Expect(err).Should(Succeed())
				Expect(parser.Position()).Should(Equal("call 3"))

				_, err = parser.Next(context.Background())
				Expect(err).Should(HaveOccurred())
				Expect(err).Should(MatchError(ErrTooManyErrors))
				Expect(parser.Position()).Should(Equal("call 4"))
			})
		})

		When("using NoErrorLimit", func() {
			It("should ignore all resumable errors", func() {
				parser = AllowErrors(parser, NoErrorLimit)

				_, err := parser.Next(context.Background())
				Expect(err).Should(Succeed())
				Expect(parser.Position()).Should(Equal("call 1"))

				_, err = parser.Next(context.Background())
				Expect(err).Should(Succeed())
				Expect(parser.Position()).Should(Equal("call 3"))

				_, err = parser.Next(context.Background())
				Expect(err).Should(Succeed())
				Expect(parser.Position()).Should(Equal("call 5"))

				_, err = parser.Next(context.Background())
				Expect(err).Should(HaveOccurred())
				Expect(err).Should(MatchError(io.EOF))
				Expect(IsNonResumableErr(err)).Should(BeTrue())
				Expect(parser.Position()).Should(Equal("call 7"))
			})
		})
	})

	Describe("OnErr", func() {
		It("should be called for each error", func() {
			inner := newMockParser(func(res chan<- string, err chan<- error) {
				err <- errors.New("fail")
				res <- "ok"
				err <- errors.New("fail")
				err <- NewNonResumableError(io.EOF)
			})

			parser := AllowErrors(inner, NoErrorLimit)

			errors := 0
			parser.OnErr(func(err error) {
				errors++
			})

			res, err := parser.Next(context.Background())
			Expect(err).Should(Succeed())
			Expect(res).Should(Equal("ok"))
			Expect(parser.Position()).Should(Equal("call 2"))

			_, err = parser.Next(context.Background())
			Expect(err).Should(HaveOccurred())
			Expect(err).Should(MatchError(io.EOF))
			Expect(IsNonResumableErr(err)).Should(BeTrue())

			Expect(errors).Should(Equal(2))
		})
	})
})
