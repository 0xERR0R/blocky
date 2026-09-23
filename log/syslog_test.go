//go:build !windows && !plan9

package log

import (
	"io"
	"net"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
)

// listen returns a UDP socket standing in for a syslog server, and the lines it receives.
func listen() (*net.UDPConn, string) {
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	Expect(err).Should(Succeed())

	conn, err := net.ListenUDP("udp", addr)
	Expect(err).Should(Succeed())

	return conn, conn.LocalAddr().String()
}

func receive(conn *net.UDPConn) string {
	Expect(conn.SetReadDeadline(time.Now().Add(5 * time.Second))).Should(Succeed())

	buf := make([]byte, 1024)

	n, _, err := conn.ReadFrom(buf)
	Expect(err).Should(Succeed())

	return string(buf[:n])
}

var _ = Describe("Syslog target", func() {
	var (
		conn   *net.UDPConn
		logger *logrus.Logger
	)

	BeforeEach(func() {
		var address string

		conn, address = listen()
		DeferCleanup(conn.Close)

		cfg := DefaultConfig()
		cfg.Level = logrus.TraceLevel
		cfg.Target = TargetTypeSyslog
		cfg.Syslog.Network = "udp"
		cfg.Syslog.Address = address

		logger = logrus.New()
		ConfigureLogger(logger, cfg)
	})

	// facility daemon (3) * 8 + severity
	DescribeTable("logs each level at the matching priority",
		func(write func(...any), priority string) {
			write("hello")

			Expect(receive(conn)).Should(HavePrefix(priority))
		},
		Entry("error is err", func(args ...any) { logger.Error(args...) }, "<27>"),
		Entry("warn is warning", func(args ...any) { logger.Warn(args...) }, "<28>"),
		Entry("info is info", func(args ...any) { logger.Info(args...) }, "<30>"),
		Entry("debug is debug", func(args ...any) { logger.Debug(args...) }, "<31>"),
		Entry("trace is debug", func(args ...any) { logger.Trace(args...) }, "<31>"),
	)

	It("carries the message and the tag", func() {
		logger.Info("a message")

		received := receive(conn)
		Expect(received).Should(ContainSubstring("blocky"))
		Expect(received).Should(ContainSubstring("a message"))
	})

	It("leaves the level and the timestamp to syslog", func() {
		logger.Info("a message")

		received := receive(conn)
		Expect(received).ShouldNot(ContainSubstring("INFO"))
		// the record's own header is the only timestamp
		Expect(received).ShouldNot(MatchRegexp(`\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}`))
	})

	It("keeps the prefix and any fields", func() {
		PrefixedLogFor(logger, "resolver").WithField("upstream", "1.1.1.1").Warn("slow")

		Expect(receive(conn)).Should(ContainSubstring("resolver: slow upstream=1.1.1.1"))
	})

	It("sends a multi-line entry as one record per line", func() {
		logger.Info("first\nsecond")

		Expect(receive(conn)).Should(ContainSubstring("first"))
		Expect(receive(conn)).Should(ContainSubstring("second"))
	})

	It("does not write the entry to the stream as well", func() {
		logger.Info("only syslog")

		Expect(logger.Out).Should(Equal(io.Discard))
	})
})

// PrefixedLogFor is PrefixedLog for a specific logger, so the spec can use the
// one pointed at the test's syslog socket.
func PrefixedLogFor(logger *logrus.Logger, prefix string) *logrus.Entry {
	return logger.WithField("prefix", prefix)
}
