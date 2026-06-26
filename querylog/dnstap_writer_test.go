package querylog

import (
	"net"
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

		It("rejects a bare tcp:// target with no host/port", func() {
			_, err := parseDnstapTarget("tcp://")
			Expect(err).Should(HaveOccurred())
		})

		It("rejects a tcp:// target with no port", func() {
			_, err := parseDnstapTarget("tcp://127.0.0.1")
			Expect(err).Should(HaveOccurred())
		})

		It("rejects a bare unix: target with no path", func() {
			_, err := parseDnstapTarget("unix:")
			Expect(err).Should(HaveOccurred())
		})

		It("rejects a relative unix socket path", func() {
			_, err := parseDnstapTarget("unix:relative/dnstap.sock")
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
			Expect(dt.GetMessage().GetSocketFamily()).Should(Equal(dnstap.SocketFamily_INET))
			Expect(dt.GetMessage().GetSocketProtocol()).Should(Equal(dnstap.SocketProtocol_UDP))
			Expect(net.IP(dt.GetMessage().GetQueryAddress()).String()).Should(Equal("192.168.1.1"))
			Expect(dt.GetMessage().GetQueryTimeSec()).Should(Equal(uint64(1_700_000_000)))
			Expect(dt.GetMessage().GetQueryTimeNsec()).Should(Equal(uint32(123)))
		})
	})

	Describe("NewDnstapWriter", func() {
		It("creates a writer for a unix target", func() {
			sockPath := filepath.Join(GinkgoT().TempDir(), "dnstap.sock")
			writer, err := NewDnstapWriter("unix:"+sockPath, time.Millisecond, "test-instance")
			Expect(err).Should(Succeed())
			Expect(writer).ShouldNot(BeNil())
			Expect(writer.Close()).Should(Succeed())
		})
	})

	Describe("Write", func() {
		var (
			queryWire    []byte
			responseWire []byte
		)

		BeforeEach(func() {
			query := new(dns.Msg)
			query.SetQuestion("example.com.", dns.TypeA)

			var err error
			queryWire, err = query.Pack()
			Expect(err).Should(Succeed())

			response := new(dns.Msg)
			response.SetReply(query)
			responseWire, err = response.Pack()
			Expect(err).Should(Succeed())
		})

		It("delivers a CLIENT_RESPONSE frame to a listening unix socket", func() {
			sockPath := filepath.Join(GinkgoT().TempDir(), "dnstap.sock")

			listener, err := net.Listen("unix", sockPath)
			Expect(err).Should(Succeed())

			received := make(chan []byte, 1)
			input := dnstap.NewFrameStreamSockInput(listener)

			go input.ReadInto(received)

			writer, err := NewDnstapWriter("unix:"+sockPath, time.Millisecond, "test-instance")
			Expect(err).Should(Succeed())

			DeferCleanup(func() {
				Expect(writer.Close()).Should(Succeed())
				_ = listener.Close()
			})

			writer.Write(&LogEntry{
				ClientIP:       "192.168.1.1",
				SocketProtocol: model.RequestProtocolUDP,
				QueryWire:      queryWire,
				ResponseWire:   responseWire,
				QueryTime:      time.Unix(1_700_000_000, 0),
				ResponseTime:   time.Unix(1_700_000_000, 0),
			})

			var raw []byte
			Eventually(received, "5s").Should(Receive(&raw))

			var dt dnstap.Dnstap
			Expect(proto.Unmarshal(raw, &dt)).Should(Succeed())
			Expect(dt.GetMessage().GetType()).Should(Equal(dnstap.Message_CLIENT_RESPONSE))
			Expect(dt.GetMessage().GetQueryMessage()).Should(Equal(queryWire))
		})

		It("does not block the caller when the collector is unreachable", func() {
			// No listener at this path: the run goroutine's WriteFrame blocks on a
			// failing dial, but Write must keep returning promptly and start dropping
			// once the buffer fills, never stalling the caller (the resolver's single
			// writeLog goroutine that must stay responsive to ctx cancellation).
			sockPath := filepath.Join(GinkgoT().TempDir(), "dnstap.sock")
			writer, err := NewDnstapWriter("unix:"+sockPath, time.Millisecond, "test-instance")
			Expect(err).Should(Succeed())

			DeferCleanup(func() {
				Expect(writer.Close()).Should(Succeed())
			})

			entry := &LogEntry{
				ClientIP:       "192.168.1.1",
				SocketProtocol: model.RequestProtocolUDP,
				QueryWire:      queryWire,
				ResponseWire:   responseWire,
				QueryTime:      time.Unix(1_700_000_000, 0),
				ResponseTime:   time.Unix(1_700_000_000, 0),
			}

			done := make(chan struct{})

			go func() {
				defer close(done)
				// Push well past the buffer capacity; with a blocked writer this would
				// hang forever if Write were not non-blocking.
				for range dnstapFrameChanCap + 100 {
					writer.Write(entry)
				}
			}()

			Eventually(done, "5s").Should(BeClosed())
		})
	})
})
