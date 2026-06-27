package querylog

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/0xERR0R/blocky/log"
	"github.com/0xERR0R/blocky/metrics"
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"

	dnstap "github.com/dnstap/golang-dnstap"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

const (
	loggerPrefixDnstapWriter = "dnstapQueryLogWriter" //nolint:gosec // log prefix, not a credential

	dnstapDefaultRetryInterval = 10 * time.Second
	dnstapDefaultWriteTimeout  = 30 * time.Second

	// dnstapFrameChanCap bounds the in-writer frame queue. Frames are handed to a
	// dedicated goroutine so the resolver's single writeLog goroutine never blocks
	// on a slow/unreachable collector; frames are dropped when this buffer fills.
	dnstapFrameChanCap = 4096
)

//nolint:gochecknoglobals
var dnstapFramesDropped = promauto.With(metrics.Reg).NewCounter(
	prometheus.CounterOpts{
		Name: "blocky_dnstap_frames_dropped_total",
		Help: "Number of dnstap query-log frames dropped because the internal buffer was full",
	},
)

type DnstapWriter struct {
	writer    dnstap.Writer
	identity  string
	logger    *logrus.Entry
	frames    chan []byte
	closeOnce sync.Once
	closed    atomic.Bool
	dropped   atomic.Uint64
}

func NewDnstapWriter(target string, flushInterval time.Duration, instanceID string) (*DnstapWriter, error) {
	addr, err := parseDnstapTarget(target)
	if err != nil {
		return nil, err
	}

	logger := log.PrefixedLog(loggerPrefixDnstapWriter)

	w := dnstap.NewSocketWriter(addr, &dnstap.SocketWriterOptions{
		FlushTimeout:  flushInterval,
		RetryInterval: dnstapDefaultRetryInterval,
		Timeout:       dnstapDefaultWriteTimeout,
		Dialer: &net.Dialer{
			Timeout: dnstapDefaultWriteTimeout,
		},
		// Surface the library's connection/reconnection diagnostics; the default
		// is a no-op logger, which makes a down collector fail completely silently.
		Logger: &dnstapLogger{entry: logger},
	})

	d := &DnstapWriter{
		writer:   w,
		identity: instanceID,
		logger:   logger,
		frames:   make(chan []byte, dnstapFrameChanCap),
	}

	go d.run()

	return d, nil
}

// run is the only goroutine that touches d.writer. socketWriter.WriteFrame may
// block indefinitely while the collector is unreachable, but that no longer stalls
// the resolver's writeLog goroutine (Write enqueues without blocking). When frames
// is closed, the queue drains and the socket is flushed and closed.
func (d *DnstapWriter) run() {
	defer func() {
		if d.closed.Load() {
			return
		}
		if err := d.writer.Close(); err != nil {
			d.logger.WithError(err).Warn("failed to close dnstap writer")
		}
	}()
	for frame := range d.frames {
		if d.closed.Load() {
			return
		}
		if _, err := d.writer.WriteFrame(frame); err != nil {
			if d.closed.Load() {
				return
			}
			d.logger.WithError(err).Warn("failed to write dnstap frame")
		}
	}
}

func parseDnstapTarget(target string) (net.Addr, error) {
	switch {
	case strings.HasPrefix(target, "unix:"):
		return resolveDnstapUnix(strings.TrimPrefix(target, "unix:"))
	case strings.HasPrefix(target, "tcp://"):
		return resolveDnstapTCP(strings.TrimPrefix(target, "tcp://"))
	case strings.HasPrefix(target, "/"):
		return resolveDnstapUnix(target)
	default:
		return nil, fmt.Errorf(
			"invalid dnstap target %q: expected unix:/path, tcp://host:port, or bare /path",
			target,
		)
	}
}

func resolveDnstapUnix(path string) (net.Addr, error) {
	// Reject empty (e.g. "unix:") and relative paths: net.ResolveUnixAddr accepts
	// both without error, so without this guard a misconfigured target slips through
	// and only surfaces later as a write that blocks forever on a bad address.
	if !strings.HasPrefix(path, "/") {
		return nil, fmt.Errorf("invalid dnstap unix target %q: socket path must be absolute", path)
	}

	return net.ResolveUnixAddr("unix", path)
}

func resolveDnstapTCP(hostport string) (net.Addr, error) {
	// SplitHostPort rejects empty (e.g. "tcp://") and port-less targets, which
	// net.ResolveTCPAddr would otherwise accept as ":0".
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return nil, fmt.Errorf("invalid dnstap tcp target %q: %w", hostport, err)
	}

	if host == "" || port == "" {
		return nil, fmt.Errorf("invalid dnstap tcp target %q: host and port are required", hostport)
	}

	return net.ResolveTCPAddr("tcp", hostport)
}

func (d *DnstapWriter) Write(entry *LogEntry) {
	if d.closed.Load() {
		return
	}
	if entry == nil || len(entry.QueryWire) == 0 || len(entry.ResponseWire) == 0 {
		return
	}
	frame, err := marshalDnstapFrame(entry, d.identity)
	if err != nil {
		d.logger.WithError(err).Warn("failed to marshal dnstap frame")

		return
	}
	// Hand the frame to the run goroutine without blocking. If the collector is
	// slow/unreachable the buffer fills and we drop here, rather than stalling the
	// caller's writeLog goroutine (which must stay responsive to ctx cancellation).
	select {
	case d.frames <- frame:
	default:
		dnstapFramesDropped.Inc()
		if n := d.dropped.Add(1); isPowerOfTen(n) {
			d.logger.Warnf(
				"dnstap frame buffer (%d) full (collector slow or unreachable), dropped %d frame(s) so far",
				dnstapFrameChanCap, n,
			)
		}
	}
}

// CleanUp implements the retention-cleanup hook of the Writer interface. dnstap is
// a streaming export with nothing to prune, so this is a no-op; lifecycle teardown
// happens in Close instead.
func (d *DnstapWriter) CleanUp() {}

// Close signals shutdown: it stops accepting frames so the run goroutine drains the
// queue and closes the socket. It returns immediately and never waits on an in-flight
// WriteFrame, so a stuck collector connection cannot hang shutdown.
func (d *DnstapWriter) Close() error {
	d.closeOnce.Do(func() {
		d.closed.Store(true)
		close(d.frames)
		if err := d.writer.Close(); err != nil {
			d.logger.WithError(err).Warn("failed to close dnstap writer on shutdown")
		}
	})

	return nil
}

func marshalDnstapFrame(entry *LogEntry, identity string) ([]byte, error) {
	msgType := dnstap.Message_CLIENT_RESPONSE
	socketFamily, queryAddr, err := clientSocketFamily(entry.ClientIP)
	if err != nil {
		return nil, err
	}
	socketProtocol, err := requestProtocol(entry.SocketProtocol)
	if err != nil {
		return nil, err
	}
	querySec, queryNsec := timeToSecNsec(entry.QueryTime)
	responseSec, responseNsec := timeToSecNsec(entry.ResponseTime)
	msg := &dnstap.Message{
		Type:             msgType.Enum(),
		SocketFamily:     socketFamily.Enum(),
		SocketProtocol:   socketProtocol.Enum(),
		QueryAddress:     queryAddr,
		QueryMessage:     entry.QueryWire,
		ResponseMessage:  entry.ResponseWire,
		QueryTimeSec:     &querySec,
		QueryTimeNsec:    &queryNsec,
		ResponseTimeSec:  &responseSec,
		ResponseTimeNsec: &responseNsec,
	}
	dt := &dnstap.Dnstap{
		Identity: []byte(identity),
		Version:  []byte(util.Version),
		Type:     dnstap.Dnstap_MESSAGE.Enum(),
		Message:  msg,
	}

	return proto.Marshal(dt)
}

func clientSocketFamily(clientIP string) (dnstap.SocketFamily, []byte, error) {
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return 0, nil, fmt.Errorf("invalid client IP %q", clientIP)
	}
	if v4 := ip.To4(); v4 != nil {
		return dnstap.SocketFamily_INET, v4, nil
	}

	return dnstap.SocketFamily_INET6, ip.To16(), nil
}

func requestProtocol(protocol model.RequestProtocol) (dnstap.SocketProtocol, error) {
	switch protocol {
	case model.RequestProtocolUDP:
		return dnstap.SocketProtocol_UDP, nil
	case model.RequestProtocolTCP:
		return dnstap.SocketProtocol_TCP, nil
	default:
		return 0, fmt.Errorf("unsupported request protocol: %s", protocol)
	}
}

func timeToSecNsec(t time.Time) (uint64, uint32) {
	return uint64(t.Unix()), uint32(t.Nanosecond()) //nolint:gosec // nanosecond fits in uint32
}

// isPowerOfTen reports whether n is 1, 10, 100, 1000, ... It is used to
// throttle drop logging to O(log n) lines while always reporting the latest
// cumulative count.
func isPowerOfTen(n uint64) bool {
	for n >= 10 {
		if n%10 != 0 {
			return false
		}
		n /= 10
	}

	return n == 1
}

// dnstapLogger adapts blocky's logrus logger onto the dnstap library's Logger
// interface (Printf(string, ...interface{})), so the library's connection and
// reconnection diagnostics reach blocky's log output instead of being discarded.
type dnstapLogger struct {
	entry *logrus.Entry
}

func (l *dnstapLogger) Printf(format string, v ...any) {
	l.entry.Warnf(format, v...)
}
