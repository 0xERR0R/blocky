package parsers

import (
	"context"
	"errors"
	"io"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
)

var _ = Describe("errorFilter", func() {
	Describe("AllowErrors", func() {
		var parser SeriesParser[struct{}]

		BeforeEach(func() {
			//	mockParser := NewMockSeriesParser[struct{}](GinkgoT())
			//	mockParser.EXPECT().Next(mock.Anything).Return(struct{}{}, nil).Once()
			//	mockParser.EXPECT().Next(mock.Anything).Return(struct{}{}, errors.New("fail")).Once()
			//	mockParser.EXPECT().Next(mock.Anything).Return(struct{}{}, nil).Once()
			//	mockParser.EXPECT().Next(mock.Anything).Return(struct{}{}, errors.New("fail")).Once()
			//	mockParser.EXPECT().Next(mock.Anything).Return(struct{}{}, nil).Once()
			//	mockParser.EXPECT().Next(mock.Anything).Return(struct{}{}, errors.New("fail")).Once()
			//	mockParser.EXPECT().Next(mock.Anything).Return(struct{}{}, NewNonResumableError(io.EOF)).Once()
			//	parser = mockParser

		})

		When("0 errors are allowed", func() {
			BeforeEach(func() {
				mockParser := NewMockSeriesParser[struct{}](GinkgoT())
				mockParser.EXPECT().Next(mock.Anything).Return(struct{}{}, nil).Once()
				mockParser.EXPECT().Next(mock.Anything).Return(struct{}{}, errors.New("fail")).Once()
				parser = mockParser
			})
			It("should fail on first error", func() {
				parser = AllowErrors(parser, 0)

				_, err := parser.Next(context.Background())
				Expect(err).Should(Succeed())

				_, err = parser.Next(context.Background())
				Expect(err).ShouldNot(Succeed())
				Expect(err).Should(MatchError(ErrTooManyErrors))
			})
		})

		When("1 error is allowed", func() {
			BeforeEach(func() {
				mockParser := NewMockSeriesParser[struct{}](GinkgoT())
				mockParser.EXPECT().Next(mock.Anything).Return(struct{}{}, nil).Once()
				mockParser.EXPECT().Next(mock.Anything).Return(struct{}{}, errors.New("fail")).Once()
				mockParser.EXPECT().Next(mock.Anything).Return(struct{}{}, nil).Once()
				mockParser.EXPECT().Next(mock.Anything).Return(struct{}{}, errors.New("fail")).Once()
				parser = mockParser
			})
			It("should fail on second error", func() {
				parser = AllowErrors(parser, 1)

				_, err := parser.Next(context.Background())
				Expect(err).Should(Succeed())

				_, err = parser.Next(context.Background())
				Expect(err).Should(Succeed())

				_, err = parser.Next(context.Background())
				Expect(err).ShouldNot(Succeed())
				Expect(err).Should(MatchError(ErrTooManyErrors))
			})
		})

		When("using NoErrorLimit", func() {
			BeforeEach(func() {
				mockParser := NewMockSeriesParser[struct{}](GinkgoT())
				mockParser.EXPECT().Next(mock.Anything).Return(struct{}{}, nil).Once()
				mockParser.EXPECT().Next(mock.Anything).Return(struct{}{}, errors.New("fail")).Once()
				mockParser.EXPECT().Next(mock.Anything).Return(struct{}{}, nil).Once()
				mockParser.EXPECT().Next(mock.Anything).Return(struct{}{}, errors.New("fail")).Once()
				mockParser.EXPECT().Next(mock.Anything).Return(struct{}{}, NewNonResumableError(io.EOF)).Once()
				parser = mockParser
			})
			It("should ignore all resumable errors", func() {
				parser = AllowErrors(parser, NoErrorLimit)

				_, err := parser.Next(context.Background())
				Expect(err).Should(Succeed())

				_, err = parser.Next(context.Background())
				Expect(err).Should(Succeed())

				_, err = parser.Next(context.Background())
				Expect(err).ShouldNot(Succeed())
				Expect(err).Should(MatchError(io.EOF))
				Expect(IsNonResumableErr(err)).Should(BeTrue())

			})
		})
	})

	Describe("OnErr", func() {
		var parser SeriesParser[string]
		BeforeEach(func() {
			inner := NewMockSeriesParser[string](GinkgoT())
			inner.EXPECT().Next(mock.Anything).Return("", errors.New("fail")).Once()
			inner.EXPECT().Next(mock.Anything).Return("ok", nil).Once()
			inner.EXPECT().Position().Return("position")
			inner.EXPECT().Next(mock.Anything).Return("", errors.New("fail")).Once()
			inner.EXPECT().Next(mock.Anything).Return("", NewNonResumableError(io.EOF)).Once()
			parser = inner
		})
		It("should be called for each error", func() {
			parser := AllowErrors(parser, NoErrorLimit)

			errors := 0
			parser.OnErr(func(err error) {
				errors++
			})

			res, err := parser.Next(context.Background())
			Expect(err).Should(Succeed())
			Expect(res).Should(Equal("ok"))

			_, err = parser.Next(context.Background())
			Expect(err).ShouldNot(Succeed())
			Expect(err).Should(MatchError(io.EOF))
			Expect(IsNonResumableErr(err)).Should(BeTrue())

			Expect(errors).Should(Equal(2))
		})
	})
})
