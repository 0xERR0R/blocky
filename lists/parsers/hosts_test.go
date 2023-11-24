package parsers

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Hosts", func() {
	var (
		sutReader io.Reader
		sut       SeriesParser[*HostsIterator]
	)

	BeforeEach(func() {
		sutReader = nil
	})

	JustBeforeEach(func() {
		sut = Hosts(sutReader)
	})

	When("parsing valid lines", func() {
		BeforeEach(func() {
			sutReader = linesReader(
				"localhost",
				"# comment",
				"  ",
				"127.0.0.1 domain.tld # comment",
				"::1 localhost alias",
				`/domain\.(tld|local)/`,
				`/^(.*\.)?2023\.xn--aptslabs-6fd\.net$/`,
				`müller.com`,
				`*.example.com`,
			)
		})

		It("succeeds", func() {
			it, err := sut.Next(context.Background())
			Expect(err).Should(Succeed())
			Expect(iteratorToList(it.ForEach)).Should(Equal([]string{"localhost"}))
			Expect(sut.Position()).Should(Equal("line 1"))

			it, err = sut.Next(context.Background())
			Expect(err).Should(Succeed())
			Expect(iteratorToList(it.ForEach)).Should(Equal([]string{"domain.tld"}))
			Expect(sut.Position()).Should(Equal("line 4"))

			it, err = sut.Next(context.Background())
			Expect(err).Should(Succeed())
			Expect(iteratorToList(it.ForEach)).Should(Equal([]string{"localhost", "alias"}))
			Expect(sut.Position()).Should(Equal("line 5"))

			it, err = sut.Next(context.Background())
			Expect(err).Should(Succeed())
			Expect(iteratorToList(it.ForEach)).Should(Equal([]string{`/domain\.(tld|local)/`}))
			Expect(sut.Position()).Should(Equal("line 6"))

			it, err = sut.Next(context.Background())
			Expect(err).Should(Succeed())
			Expect(iteratorToList(it.ForEach)).Should(Equal([]string{`/^(.*\.)?2023\.xn--aptslabs-6fd\.net$/`}))
			Expect(sut.Position()).Should(Equal("line 7"))

			it, err = sut.Next(context.Background())
			Expect(err).Should(Succeed())
			Expect(iteratorToList(it.ForEach)).Should(Equal([]string{`xn--mller-kva.com`}))
			Expect(sut.Position()).Should(Equal("line 8"))

			it, err = sut.Next(context.Background())
			Expect(err).Should(Succeed())
			Expect(iteratorToList(it.ForEach)).Should(Equal([]string{"*.example.com"}))
			Expect(sut.Position()).Should(Equal("line 9"))

			_, err = sut.Next(context.Background())
			Expect(err).Should(HaveOccurred())
			Expect(err).Should(MatchError(io.EOF))
			Expect(IsNonResumableErr(err)).Should(BeTrue())
			Expect(sut.Position()).Should(Equal("line 10"))
		})
	})

	When("parsing invalid lines", func() {
		It("fails", func() {
			lines := []string{
				"invalidIP localhost",
				"!notadomain!",
				"xn---mllerk1va.com",
				`/invalid regex ??/`,
				"invalid.*.wildcard",
			}

			for _, line := range lines {
				sut := Hosts(strings.NewReader(line))

				_, err := sut.Next(context.Background())
				Expect(err).Should(HaveOccurred())
				Expect(IsNonResumableErr(err)).ShouldNot(BeTrue())
				Expect(sut.Position()).Should(Equal("line 1"))
			}
		})
	})

	Describe("HostsIterator.ForEachHost", func() {
		var entry *HostsIterator

		BeforeEach(func() {
			sutReader = linesReader(
				"domain.tld",
				"127.0.0.1 domain.tld alias1 alias2",
			)
		})

		JustBeforeEach(func() {
			var err error

			entry, err = sut.Next(context.Background())
			Expect(err).Should(Succeed())
			Expect(iteratorToList(entry.forEachHost)).Should(Equal([]string{"domain.tld"}))
			Expect(sut.Position()).Should(Equal("line 1"))

			entry, err = sut.Next(context.Background())
			Expect(err).Should(Succeed())
			Expect(iteratorToList(entry.forEachHost)).Should(Equal([]string{"domain.tld", "alias1", "alias2"}))
			Expect(sut.Position()).Should(Equal("line 2"))
		})

		It("calls back with the hosts", func() {})

		When("callback returns error", func() {
			It("fails", func() {
				expectedErr := errors.New("fail")

				err := entry.forEachHost(func(host string) error {
					return expectedErr
				})
				Expect(err).Should(HaveOccurred())
				Expect(err).Should(MatchError(expectedErr))
			})
		})
	})
})

var _ = Describe("HostsFile", func() {
	var (
		sutReader io.Reader
		sut       SeriesParser[*HostsFileEntry]
	)

	BeforeEach(func() {
		sutReader = nil
	})

	JustBeforeEach(func() {
		sut = HostsFile(sutReader)
	})

	When("parsing valid lines", func() {
		BeforeEach(func() {
			sutReader = linesReader(
				"127.0.0.1 localhost",
				"# comment",
				"  ",
				"::1 localhost # comment",
				"0.0.0.0%lo0 ipWithInterface",
			)
		})

		It("succeeds", func() {
			entry, err := sut.Next(context.Background())
			Expect(err).Should(Succeed())
			Expect(entry.IP).Should(Equal(net.ParseIP("127.0.0.1")))
			Expect(entry.Name).Should(Equal("localhost"))
			Expect(entry.Aliases).Should(BeEmpty())
			Expect(sut.Position()).Should(Equal("line 1"))

			entry, err = sut.Next(context.Background())
			Expect(err).Should(Succeed())
			Expect(entry.IP).Should(Equal(net.IPv6loopback))
			Expect(entry.Name).Should(Equal("localhost"))
			Expect(entry.Aliases).Should(BeEmpty())
			Expect(sut.Position()).Should(Equal("line 4"))

			entry, err = sut.Next(context.Background())
			Expect(err).Should(Succeed())
			Expect(entry.IP).Should(Equal(net.IPv4zero))
			Expect(entry.Name).Should(Equal("ipWithInterface"))
			Expect(entry.Aliases).Should(BeEmpty())
			Expect(sut.Position()).Should(Equal("line 5"))

			_, err = sut.Next(context.Background())
			Expect(err).Should(HaveOccurred())
			Expect(err).Should(MatchError(io.EOF))
			Expect(IsNonResumableErr(err)).Should(BeTrue())
			Expect(sut.Position()).Should(Equal("line 6"))
		})

		When("there are aliases", func() {
			BeforeEach(func() {
				sutReader = linesReader(
					"127.0.0.1 localhost alias1 alias2 # comment",
				)
			})

			It("parses them", func() {
				entry, err := sut.Next(context.Background())
				Expect(err).Should(Succeed())
				Expect(entry.IP).Should(Equal(net.ParseIP("127.0.0.1")))
				Expect(entry.Name).Should(Equal("localhost"))
				Expect(entry.Aliases).Should(Equal([]string{"alias1", "alias2"}))
				Expect(sut.Position()).Should(Equal("line 1"))

				_, err = sut.Next(context.Background())
				Expect(err).Should(HaveOccurred())
				Expect(err).Should(MatchError(io.EOF))
				Expect(IsNonResumableErr(err)).Should(BeTrue())
				Expect(sut.Position()).Should(Equal("line 2"))
			})
		})
	})

	When("parsing invalid lines", func() {
		It("fails", func() {
			lines := []string{
				"127.0.0.1",
				"localhost",
				"localhost localhost",
				"::1 # localhost # comment",
				"::1 toolong" + strings.Repeat("a", maxDomainNameLength),
			}

			for _, line := range lines {
				sut := HostsFile(strings.NewReader(line))

				_, err := sut.Next(context.Background())
				Expect(err).Should(HaveOccurred())
				Expect(IsNonResumableErr(err)).ShouldNot(BeTrue())
				Expect(sut.Position()).Should(Equal("line 1"))
			}
		})
	})

	Describe("HostsFileEntry.forEachHost", func() {
		var entry *HostsFileEntry

		BeforeEach(func() {
			sutReader = linesReader(
				"127.0.0.1 domain.tld alias1 alias2",
			)
		})

		JustBeforeEach(func() {
			var err error

			entry, err = sut.Next(context.Background())
			Expect(err).Should(Succeed())
			Expect(iteratorToList(entry.forEachHost)).Should(Equal([]string{"domain.tld", "alias1", "alias2"}))
			Expect(sut.Position()).Should(Equal("line 1"))
		})

		It("calls back with the host", func() {})

		When("callback returns an error immediately", func() {
			It("fails", func() {
				expectedErr := errors.New("fail")

				err := entry.forEachHost(func(host string) error {
					return expectedErr
				})
				Expect(err).Should(HaveOccurred())
				Expect(err).Should(MatchError(expectedErr))
			})
		})

		When("callback returns an error on further calls", func() {
			It("fails", func() {
				expectedErr := errors.New("fail")

				firstCall := true

				err := entry.forEachHost(func(host string) error {
					if firstCall {
						firstCall = false

						return nil
					}

					return expectedErr
				})
				Expect(err).Should(HaveOccurred())
				Expect(err).Should(MatchError(expectedErr))
			})
		})
	})
})

var _ = Describe("HostList", func() {
	var (
		sutReader io.Reader
		sut       SeriesParser[*HostListEntry]
	)

	BeforeEach(func() {
		sutReader = nil
	})

	JustBeforeEach(func() {
		sut = HostList(sutReader)
	})

	When("parsing valid lines", func() {
		BeforeEach(func() {
			sutReader = linesReader(
				"localhost",
				"# comment",
				"  ",
				"domain.tld # comment",

				// http://www.i18nguy.com/markup/idna-examples.html
				"belgië.icom.museum",
				"الأردن.icom.museum",
				"한국.icom.museum",

				// Domain name w/ rune not supported by `idna.Lookup`
				"domain_underscore.tld",

				// invalid domain names we want to support
				"-start-with-a-hyphen.com",
				"end-with-a-hyphen-.com",
			)
		})

		It("succeeds", func() {
			entry, err := sut.Next(context.Background())
			Expect(err).Should(Succeed())
			Expect(entry.String()).Should(Equal("localhost"))
			Expect(sut.Position()).Should(Equal("line 1"))

			entry, err = sut.Next(context.Background())
			Expect(err).Should(Succeed())
			Expect(entry.String()).Should(Equal("domain.tld"))
			Expect(sut.Position()).Should(Equal("line 4"))

			entry, err = sut.Next(context.Background())
			Expect(err).Should(Succeed())
			Expect(entry.String()).Should(Equal("xn--belgi-rsa.icom.museum"))
			Expect(sut.Position()).Should(Equal("line 5"))

			entry, err = sut.Next(context.Background())
			Expect(err).Should(Succeed())
			Expect(entry.String()).Should(Equal("xn--igbhzh7gpa.icom.museum"))
			Expect(sut.Position()).Should(Equal("line 6"))

			entry, err = sut.Next(context.Background())
			Expect(err).Should(Succeed())
			Expect(entry.String()).Should(Equal("xn--3e0b707e.icom.museum"))
			Expect(sut.Position()).Should(Equal("line 7"))

			entry, err = sut.Next(context.Background())
			Expect(err).Should(Succeed())
			Expect(entry.String()).Should(Equal("domain_underscore.tld"))
			Expect(sut.Position()).Should(Equal("line 8"))

			entry, err = sut.Next(context.Background())
			Expect(err).Should(Succeed())
			Expect(entry.String()).Should(Equal("-start-with-a-hyphen.com"))
			Expect(sut.Position()).Should(Equal("line 9"))

			entry, err = sut.Next(context.Background())
			Expect(err).Should(Succeed())
			Expect(entry.String()).Should(Equal("end-with-a-hyphen-.com"))
			Expect(sut.Position()).Should(Equal("line 10"))

			_, err = sut.Next(context.Background())
			Expect(err).Should(HaveOccurred())
			Expect(err).Should(MatchError(io.EOF))
			Expect(IsNonResumableErr(err)).Should(BeTrue())
			Expect(sut.Position()).Should(Equal("line 11"))
		})
	})

	When("parsing invalid lines", func() {
		It("fails", func() {
			lines := []string{
				"127.0.0.1 localhost",
				"localhost localhost",
				`/invalid regex ??/`,
				"toolong" + strings.Repeat("a", maxDomainNameLength),
			}

			for _, line := range lines {
				sut := HostList(strings.NewReader(line))

				_, err := sut.Next(context.Background())
				Expect(err).Should(HaveOccurred())
				Expect(IsNonResumableErr(err)).ShouldNot(BeTrue())
				Expect(sut.Position()).Should(Equal("line 1"))
			}
		})
	})

	Describe("HostListEntry.forEachHost", func() {
		var entry *HostListEntry

		BeforeEach(func() {
			sutReader = linesReader(
				"domain.tld",
			)
		})

		JustBeforeEach(func() {
			var err error

			entry, err = sut.Next(context.Background())
			Expect(err).Should(Succeed())
			Expect(iteratorToList(entry.forEachHost)).Should(Equal([]string{"domain.tld"}))
			Expect(sut.Position()).Should(Equal("line 1"))
		})

		It("calls back with the host", func() {})

		When("callback returns error", func() {
			It("fails", func() {
				expectedErr := errors.New("fail")

				err := entry.forEachHost(func(host string) error {
					return expectedErr
				})
				Expect(err).Should(HaveOccurred())
				Expect(err).Should(MatchError(expectedErr))
			})
		})
	})
})
