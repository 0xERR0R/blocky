package querylog

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/0xERR0R/blocky/log"
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"
	dnstap "github.com/dnstap/golang-dnstap"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

const (
	loggerPrefixDnstapWriter = "dnstapQueryLogWriter" //nolint:gosec // log prefix, not a credential

	dnstapDefaultRetryInterval = 10 * time.Second
	dnstapDefaultWriteTimeout  = 30 * time.Second
)

type DnstapWriter struct {
	writer   dnstap.Writer
	identity string
	logger   *logrus.Entry
}

func NewDnstapWriter(target string, flushInterval time.Duration, instanceID string) (*DnstapWriter, error) {
	addr, err := parseDnstapTarget(target)
	if err != nil {
		return nil, err
	}

	w := dnstap.NewSocketWriter(addr, &dnstap.SocketWriterOptions{
		FlushTimeout:  flushInterval,
		RetryInterval: dnstapDefaultRetryInterval,
		Timeout:       dnstapDefaultWriteTimeout,
		Dialer: &net.Dialer{
			Timeout: dnstapDefaultWriteTimeout,
		},
	})

	return &DnstapWriter{
		writer:   w,
		identity: instanceID,
		logger:   log.PrefixedLog(loggerPrefixDnstapWriter),
	}, nil
}

func parseDnstapTarget(target string) (net.Addr, error) {
	switch {
	case strings.HasPrefix(target, "unix:"):
		return net.ResolveUnixAddr("unix", strings.TrimPrefix(target, "unix:"))
	case strings.HasPrefix(target, "tcp://"):
		return net.ResolveTCPAddr("tcp", strings.TrimPrefix(target, "tcp://"))
	case strings.HasPrefix(target, "/"):
		return net.ResolveUnixAddr("unix", target)
	default:
		return nil, fmt.Errorf(
			"invalid dnstap target %q: expected unix:/path, tcp://host:port, or bare /path",
			target,
		)
	}
}

func (d *DnstapWriter) Write(entry *LogEntry) {
	if entry == nil || len(entry.QueryWire) == 0 || len(entry.ResponseWire) == 0 {
		return
	}
	frame, err := marshalDnstapFrame(entry, d.identity)
	if err != nil {
		d.logger.WithError(err).Warn("failed to marshal dnstap frame")

		return
	}
	if _, err := d.writer.WriteFrame(frame); err != nil {
		d.logger.WithError(err).Warn("failed to write dnstap frame")
	}
}

func (d *DnstapWriter) CleanUp() {
	if err := d.writer.Close(); err != nil {
		d.logger.WithError(err).Warn("failed to close dnstap writer")
	}
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
