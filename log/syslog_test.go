//go:build !windows && !plan9

package log

import (
	"bytes"
	"io"
	"net"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	prefixed "github.com/x-cray/logrus-prefixed-formatter"
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

	It("maps every declared facility to a syslog priority", func() {
		for _, facility := range SyslogFacilityNames() {
			_, found := syslogFacilities[SyslogFacility(facility)]
			Expect(found).Should(BeTrue(), "facility %q must have a syslog priority", facility)
		}
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

	It("applies indentation before formatting the syslog entry", func() {
		WithIndent(logger.WithField("prefix", "resolver"), "  ", func(entry *logrus.Entry) {
			entry.Info("indented")
		})

		Expect(receive(conn)).Should(ContainSubstring("resolver:   indented"))
	})

	It("stops sending to syslog when reconfigured away from it", func() {
		ConfigureLogger(logger, DefaultConfig())

		Expect(logger.Out).ShouldNot(BeAssignableToTypeOf(&syslogWriter{}))

		out := new(bytes.Buffer)
		logger.SetOutput(out)
		logger.Info("stdout")
		Expect(out.String()).Should(ContainSubstring("stdout"))

		Expect(conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))).Should(Succeed())
		_, _, err := conn.ReadFrom(make([]byte, 1024))
		Expect(err).Should(HaveOccurred(), "reconfigured logger must not send to its old syslog destination")
	})

	It("keeps the hooks registered before it", func() {
		hook := &MockLoggerHook{}
		hook.On("Fire").Return(nil)
		logger.AddHook(hook)

		cfg := DefaultConfig()
		cfg.Target = TargetTypeSyslog
		cfg.Syslog.Network = "udp"
		cfg.Syslog.Address = conn.LocalAddr().String()
		ConfigureLogger(logger, cfg)

		logger.Info("hooked")

		Expect(hook.Messages).Should(ContainElement("hooked"))
		Expect(receive(conn)).Should(ContainSubstring("hooked"))
	})

	DescribeTable("closes the syslog connection when reconfigured",
		func(next func() *Config) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			Expect(err).Should(Succeed())
			DeferCleanup(listener.Close)

			cfg := DefaultConfig()
			cfg.Target = TargetTypeSyslog
			cfg.Syslog.Network = "tcp"
			cfg.Syslog.Address = listener.Addr().String()
			ConfigureLogger(logger, cfg)

			client, err := listener.Accept()
			Expect(err).Should(Succeed())
			DeferCleanup(client.Close)

			ConfigureLogger(logger, next())

			Expect(client.SetReadDeadline(time.Now().Add(time.Second))).Should(Succeed())
			_, err = client.Read(make([]byte, 1))
			Expect(err).Should(Equal(io.EOF))
		},
		Entry("to a stream", DefaultConfig),
		Entry("to syslog again", func() *Config {
			cfg := DefaultConfig()
			cfg.Target = TargetTypeSyslog
			cfg.Syslog.Network = "udp"
			cfg.Syslog.Address = conn.LocalAddr().String()

			return cfg
		}),
	)

	It("sends a multi-line entry as one record per line", func() {
		logger.Info("first\nsecond")

		Expect(receive(conn)).Should(ContainSubstring("first"))
		Expect(receive(conn)).Should(ContainSubstring("second"))
	})

	It("writes through its own output, never a discarding one", func() {
		Expect(logger.Out).Should(BeAssignableToTypeOf(&syslogWriter{}))
		Expect(logger.Out).ShouldNot(Equal(io.Discard))
	})

	When("syslog can't be used", func() {
		var cfg *Config

		BeforeEach(func() {
			cfg = DefaultConfig()
			cfg.Target = TargetTypeSyslog
		})

		It("rejects an address without a network", func() {
			cfg.Syslog.Address = "loghost:514"

			_, err := newSyslogWriter(cfg.Syslog)
			Expect(err).Should(MatchError(ContainSubstring("needs a network")))
		})

		It("falls back to stderr with the regular text format", func() {
			cfg.Syslog.Address = "loghost:514"

			ConfigureLogger(logger, cfg)

			Expect(logger.Out).ShouldNot(BeAssignableToTypeOf(&syslogWriter{}))
			Expect(logger.Formatter).Should(BeAssignableToTypeOf(&prefixed.TextFormatter{}))
		})
	})
})

// PrefixedLogFor is PrefixedLog for a specific logger, so the spec can use the
// one pointed at the test's syslog socket.
func PrefixedLogFor(logger *logrus.Logger, prefix string) *logrus.Entry {
	return logger.WithField("prefix", prefix)
}
