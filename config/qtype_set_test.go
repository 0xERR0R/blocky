package config

import (
	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("QTypeSet", func() {
	Describe("NewQTypeSet", func() {
		It("should insert given qTypes", func() {
			set := NewQTypeSet(dns.Type(dns.TypeA))
			Expect(set).Should(HaveKey(QType(dns.TypeA)))
			Expect(set.Contains(dns.Type(dns.TypeA))).Should(BeTrue())

			Expect(set).ShouldNot(HaveKey(QType(dns.TypeAAAA)))
			Expect(set.Contains(dns.Type(dns.TypeAAAA))).ShouldNot(BeTrue())
		})
	})

	Describe("Insert", func() {
		It("should insert given qTypes", func() {
			set := NewQTypeSet()

			Expect(set).ShouldNot(HaveKey(QType(dns.TypeAAAA)))
			Expect(set.Contains(dns.Type(dns.TypeAAAA))).ShouldNot(BeTrue())

			set.Insert(dns.Type(dns.TypeAAAA))

			Expect(set).Should(HaveKey(QType(dns.TypeAAAA)))
			Expect(set.Contains(dns.Type(dns.TypeAAAA))).Should(BeTrue())
		})
	})
})

var _ = Describe("QType", func() {
	Describe("UnmarshalText", func() {
		It("Should parse existing DNS type as string", func() {
			t := QType(0)
			err := t.UnmarshalText([]byte("AAAA"))
			Expect(err).Should(Succeed())
			Expect(t).Should(Equal(QType(dns.TypeAAAA)))
			Expect(t.String()).Should(Equal("AAAA"))
		})

		It("should fail if DNS type does not exist", func() {
			t := QType(0)
			err := t.UnmarshalText([]byte("WRONGTYPE"))
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("unknown DNS query type: 'WRONGTYPE'"))
		})

		It("should fail if wrong YAML format", func() {
			d := QType(0)
			err := d.UnmarshalText([]byte("some err"))
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("unknown DNS query type: 'some err'"))
		})
	})
})
