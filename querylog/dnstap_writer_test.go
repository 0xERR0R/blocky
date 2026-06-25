package querylog

import (
	"path/filepath"
	"time"

	"github.com/0xERR0R/blocky/model"
	dnstap "github.com/dnstap/golang-dnstap"
	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"google.golang.org/protobuf/proto"
)

var _ = Describe("DnstapWriter", func() {
	Describe("parseDnstapTarget", func() {
		It("parses unix: prefix", func() {
			addr, err := parseDnstapTarget("unix:/var/run/dnstap.sock")
			Expect(err).Should(Succeed())
			Expect(addr.Network()).Should(Equal("unix"))
			Expect(addr.String()).Should(Equal("/var/run/dnstap.sock"))
		})

		It("parses bare unix path", func() {
			addr, err := parseDnstapTarget("/var/run/dnstap.sock")
			Expect(err).Should(Succeed())
			Expect(addr.Network()).Should(Equal("unix"))
			Expect(addr.String()).Should(Equal("/var/run/dnstap.sock"))
		})

		It("parses tcp:// target", func() {
			addr, err := parseDnstapTarget("tcp://127.0.0.1:6000")
			Expect(err).Should(Succeed())
			Expect(addr.Network()).Should(Equal("tcp"))
			Expect(addr.String()).Should(Equal("127.0.0.1:6000"))
		})

		It("rejects invalid target", func() {
			_, err := parseDnstapTarget("not-a-valid-target")
			Expect(err).Should(HaveOccurred())
		})
	})

	Describe("marshalDnstapFrame", func() {
		It("builds a CLIENT_RESPONSE frame", func() {
			query := new(dns.Msg)
			query.SetQuestion("example.com.", dns.TypeA)
			queryWire, err := query.Pack()
			Expect(err).Should(Succeed())

			response := new(dns.Msg)
			response.SetReply(query)
			responseWire, err := response.Pack()
			Expect(err).Should(Succeed())

			queryTime := time.Unix(1_700_000_000, 123)
			responseTime := queryTime.Add(5 * time.Millisecond)

			frame, err := marshalDnstapFrame(&LogEntry{
				ClientIP:       "192.168.1.1",
				SocketProtocol: model.RequestProtocolUDP,
				QueryWire:      queryWire,
				ResponseWire:   responseWire,
				QueryTime:      queryTime,
				ResponseTime:   responseTime,
			}, "blocky-test")
			Expect(err).Should(Succeed())

			var dt dnstap.Dnstap
			Expect(proto.Unmarshal(frame, &dt)).Should(Succeed())
			Expect(dt.GetType()).Should(Equal(dnstap.Dnstap_MESSAGE))
			Expect(string(dt.GetIdentity())).Should(Equal("blocky-test"))
			Expect(dt.GetMessage().GetType()).Should(Equal(dnstap.Message_CLIENT_RESPONSE))
			Expect(dt.GetMessage().GetQueryMessage()).Should(Equal(queryWire))
			Expect(dt.GetMessage().GetResponseMessage()).Should(Equal(responseWire))
		})
	})

	Describe("NewDnstapWriter", func() {
		It("creates a writer for a unix target", func() {
			sockPath := filepath.Join(GinkgoT().TempDir(), "dnstap.sock")
			writer, err := NewDnstapWriter("unix:"+sockPath, time.Millisecond, "test-instance")
			Expect(err).Should(Succeed())
			Expect(writer).ShouldNot(BeNil())
			writer.CleanUp()
		})
	})
})
