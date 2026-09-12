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
				`||0-c1j0.lat^`,
				"xn----7sbhlqiujscje.xn--p1ai",
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

			it, err = sut.Next(context.Background())
			Expect(err).Should(Succeed())
			Expect(iteratorToList(it.ForEach)).Should(Equal([]string{"0-c1j0.lat"}))
			Expect(sut.Position()).Should(Equal("line 10"))

			it, err = sut.Next(context.Background())
			Expect(err).Should(Succeed())
			Expect(iteratorToList(it.ForEach)).Should(Equal([]string{"xn----7sbhlqiujscje.xn--p1ai"}))
			Expect(sut.Position()).Should(Equal("line 11"))

			_, err = sut.Next(context.Background())
			Expect(err).Should(HaveOccurred())
			Expect(err).Should(MatchError(io.EOF))
			Expect(IsNonResumableErr(err)).Should(BeTrue())
			Expect(sut.Position()).Should(Equal("line 12"))
		})
	})

	When("parsing entries that need normalization", func() {
		It("emits the form DNS queries carry", func() {
			cases := []struct {
				line  string
				hosts []string
			}{
				// URL-style IPv6 literals
				{"[2001:db8::1]", []string{"2001:db8::1"}},
				{"||[::1]^", []string{"::1"}},
				// Unicode, punycode and mixed labels normalize to lowercase A-labels
				{"MÜNCHEN.example.de", []string{"xn--mnchen-3ya.example.de"}},
				{"XN--MNCHEN-3YA.example.de", []string{"xn--mnchen-3ya.example.de"}},
				{"xn--mnchen-3ya.café.com", []string{"xn--mnchen-3ya.xn--caf-dma.com"}},
				{"имяенн.010.xn--p1acf", []string{"xn--e1afmfa9h.010.xn--p1acf"}},
				// the same applies to hosts file names and wildcards
				{"0.0.0.0 münchen.example.de bücher.example.de", []string{"xn--mnchen-3ya.example.de", "xn--bcher-kva.example.de"}},
				{"*.münchen.example.de", []string{"*.xn--mnchen-3ya.example.de"}},
				// trailing root dots survive, with and without IDNA
				{"example.com.", []string{"example.com."}},
				{"münchen.example.de.", []string{"xn--mnchen-3ya.example.de."}},
				{"*.münchen.example.de.", []string{"*.xn--mnchen-3ya.example.de."}},
				{"0.0.0.0 münchen.example.de.", []string{"xn--mnchen-3ya.example.de."}},
				{"example\u3002com\u3002", []string{"example.com."}},
				// regexes stay as written
				{"/[A-Z]+\\.café/", []string{"/[A-Z]+\\.café/"}},
			}

			for _, c := range cases {
				sut := Hosts(strings.NewReader(c.line))

				it, err := sut.Next(context.Background())
				Expect(err).Should(Succeed(), c.line)
				Expect(iteratorToList(it.ForEach)).Should(Equal(c.hosts), c.line)
			}
		})
	})

	When("parsing invalid lines", func() {
		It("fails", func() {
			lines := []string{
				"invalidIP localhost",
				"xn---mllerk1va.com",
				"0.0.0.0 xn---mllerk1va.com",
				"*.xn---mllerk1va.com",
				`/invalid regex ??/`,
				"invalid.*.wildcard",
				// brackets are only valid around an IPv6 address
				"[example.com]",
				"[1.2.3.4]",
				"[fe80::1%eth0]",
				"[::1]:53",
				"[::1",
				// Base64-like junk and malformed IDNs stay rejected, not repaired into host names
				"dGVzdA==",
				"YWJj+/==",
				"münchen..example.de",
				"münchen/example.de",
				// labels that vanish in the IDNA mapping (empty "xn--" payload, ignored
				// code points only) would leave a trailing dot the cache folds away,
				// turning "*.com.xn--" into a rule for every .com name
				"xn--",
				"com.xn--",
				"0.0.0.0 com.xn--",
				"*.com.xn--",
				"*.xn--.com",
				"*.com.\u00ad",
				"*.\u200b.com",
				"*.com\u3002xn--", // ideographic full stop as the separator
				"com\uff0e\u00ad", // fullwidth full stop
				"\ufeff",
				// wildcard suffixes are validated like plain entries
				"*.",
				"*..com",
				"*.com/path",
			}

			for _, line := range lines {
				sut := Hosts(strings.NewReader(line))

				_, err := sut.Next(context.Background())
				Expect(err).Should(HaveOccurred(), line)
				Expect(IsNonResumableErr(err)).ShouldNot(BeTrue())
				Expect(sut.Position()).Should(Equal("line 1"))
			}
		})

		It("reports them with their position and counts them against the error limit", func() {
			sut := AllowErrors(Hosts(linesReader(
				"[2001:db8::1]",
				"dGVzdA==",
				"MÜNCHEN.example.de",
				"YWJj+/==",
				"valid.example.com",
			)), 1)

			var errs []string

			sut.OnErr(func(err error) {
				errs = append(errs, err.Error())
			})

			it, err := sut.Next(context.Background())
			Expect(err).Should(Succeed())
			Expect(iteratorToList(it.ForEach)).Should(Equal([]string{"2001:db8::1"}))

			it, err = sut.Next(context.Background())
			Expect(err).Should(Succeed())
			Expect(iteratorToList(it.ForEach)).Should(Equal([]string{"xn--mnchen-3ya.example.de"}))
			Expect(sut.Position()).Should(Equal("line 3"))

			_, err = sut.Next(context.Background())
			Expect(err).Should(MatchError(ErrTooManyErrors))
			Expect(sut.Position()).Should(Equal("line 4"))

			Expect(errs).Should(HaveLen(2))
			Expect(errs[0]).Should(SatisfyAll(HavePrefix("line 2: "), ContainSubstring("invalid domain name: dGVzdA==")))
			Expect(errs[1]).Should(SatisfyAll(HavePrefix("line 4: "), ContainSubstring("invalid domain name: YWJj+/==")))
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
				"localhost localhost", //nolint:dupword
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
				"localhost localhost", //nolint:dupword
				`/invalid regex ??/`,
				"/", // a lone slash is not a valid /regex/ delimiter pair
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
