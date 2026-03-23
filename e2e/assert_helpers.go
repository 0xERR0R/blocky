package e2e

import (
	"context"
	"time"

	. "github.com/0xERR0R/blocky/helpertest"
	"github.com/0xERR0R/blocky/util"
	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/types"
	"github.com/testcontainers/testcontainers-go"
)

// expectResolve sends a DNS query and asserts the response matches the expected record.
// Optional extra matchers (e.g., HaveTTL) are applied in addition to BeDNSRecord.
func expectResolve(
	ctx context.Context, blocky testcontainers.Container,
	domain string, qType dns.Type, expected string, extra ...types.GomegaMatcher,
) {
	GinkgoHelper()

	msg := util.NewMsgWithQuestion(domain, qType)

	matchers := []types.GomegaMatcher{BeDNSRecord(domain, qType, expected)}
	matchers = append(matchers, extra...)

	Expect(doDNSRequest(ctx, blocky, msg)).Should(SatisfyAll(matchers...))
}

// expectNXDomain sends a DNS query and asserts the response is NXDOMAIN with no answer.
func expectNXDomain(
	ctx context.Context, blocky testcontainers.Container,
	domain string, qType dns.Type,
) {
	GinkgoHelper()

	msg := util.NewMsgWithQuestion(domain, qType)
	resp, err := doDNSRequest(ctx, blocky, msg)
	Expect(err).Should(Succeed())
	Expect(resp.Rcode).Should(Equal(dns.RcodeNameError))
	Expect(resp.Answer).Should(BeEmpty())
}

// expectNoAnswer sends a DNS query and asserts the response is NOERROR with no answer.
func expectNoAnswer(
	ctx context.Context, blocky testcontainers.Container,
	domain string, qType dns.Type,
) {
	GinkgoHelper()

	msg := util.NewMsgWithQuestion(domain, qType)
	resp, err := doDNSRequest(ctx, blocky, msg)
	Expect(err).Should(Succeed())
	Expect(resp.Rcode).Should(Equal(dns.RcodeSuccess))
	Expect(resp.Answer).Should(BeEmpty())
}

// expectRefused sends a DNS query and asserts the response is REFUSED.
func expectRefused(
	ctx context.Context, blocky testcontainers.Container,
	domain string, qType dns.Type,
) {
	GinkgoHelper()

	msg := util.NewMsgWithQuestion(domain, qType)
	resp, err := doDNSRequest(ctx, blocky, msg)
	Expect(err).Should(Succeed())
	Expect(resp.Rcode).Should(Equal(dns.RcodeRefused))
}

// expectEventually sends a DNS query repeatedly until the expected record is returned.
// Optional extra matchers (e.g., HaveTTL) are applied in addition to BeDNSRecord.
func expectEventually(
	ctx context.Context, blocky testcontainers.Container,
	domain string, qType dns.Type, expected string, timeout time.Duration,
	extra ...types.GomegaMatcher,
) {
	GinkgoHelper()

	msg := util.NewMsgWithQuestion(domain, qType)

	matchers := []types.GomegaMatcher{BeDNSRecord(domain, qType, expected)}
	matchers = append(matchers, extra...)

	Eventually(func() (*dns.Msg, error) {
		return doDNSRequest(ctx, blocky, msg)
	}, timeout, 200*time.Millisecond).Should(SatisfyAll(matchers...))
}
