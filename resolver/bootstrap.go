package resolver

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/log"
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"
	"github.com/hashicorp/go-multierror"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"golang.org/x/exp/maps"
)

const (
	defaultTimeout = 5 * time.Second
)

// Bootstrap allows resolving hostnames using the configured bootstrap DNS.
type Bootstrap struct {
	log *logrus.Entry

	resolver    Resolver
	bootstraped bootstrapedResolvers

	connectIPVersion config.IPVersion
	timeout          time.Duration

	// To allow replacing during tests
	systemResolver *net.Resolver
	dialer         interface {
		DialContext(ctx context.Context, network, addr string) (net.Conn, error)
	}
}

// NewBootstrap creates and returns a new Bootstrap.
// Internally, it uses a CachingResolver and an UpstreamResolver.
func NewBootstrap(ctx context.Context, cfg *config.Config) (b *Bootstrap, err error) {
	logger := log.PrefixedLog("bootstrap")

	timeout := defaultTimeout
	if cfg.Upstreams.Timeout.IsAboveZero() {
		timeout = cfg.Upstreams.Timeout.ToDuration()
	}

	// Create b in multiple steps: Bootstrap and UpstreamResolver have a cyclic dependency
	// This also prevents the GC to clean up these two structs, but is not currently an
	// issue since they stay allocated until the process terminates
	b = &Bootstrap{
		log:              logger,
		connectIPVersion: cfg.ConnectIPVersion,

		systemResolver: net.DefaultResolver,
		timeout:        timeout,
		dialer: &net.Dialer{
			Timeout: timeout,
		},
	}

	bootstraped, err := newBootstrapedResolvers(b, cfg.BootstrapDNS, cfg.Upstreams)
	if err != nil {
		return nil, err
	}

	if len(bootstraped) == 0 {
		logger.Infof("bootstrapDns is not configured, will use system resolver")

		return b, nil
	}

	pbCfg := config.NewUpstreamGroup("<bootstrap>", cfg.Upstreams, nil)
	pbCfg.Upstreams.Groups = nil // To be on the safe side it doesn't try to use anything besides the bootstrap

	// Always enable prefetching to avoid stalling user requests
	// Otherwise, a request to blocky could end up waiting for 2 DNS requests:
	//   1. lookup the DNS server IP
	//   2. forward the user request to the server looked-up in 1
	cachingCfg := cfg.Caching
	cachingCfg.EnablePrefetch()

	if !cachingCfg.MinCachingTime.IsAboveZero() {
		// Set a min time in case the user didn't to avoid prefetching too often
		cachingCfg.MinCachingTime = config.Duration(time.Hour)
	}

	b.bootstraped = bootstraped

	b.resolver = Chain(
		NewFilteringResolver(cfg.Filtering),
		// false: no metrics, to not overwrite the main blocking resolver ones
		newCachingResolver(ctx, cachingCfg, nil, false),
		newParallelBestResolver(pbCfg, bootstraped.Resolvers()),
	)

	return b, nil
}

func (b *Bootstrap) UpstreamIPs(ctx context.Context, r *UpstreamResolver) (*IPSet, error) {
	hostname := r.cfg.Host

	if ip := net.ParseIP(hostname); ip != nil { // nil-safe when hostname is an IP: makes writing test easier
		return newIPSet([]net.IP{ip}), nil
	}

	ips, err := b.resolveUpstream(ctx, r, hostname)
	if err != nil {
		return nil, err
	}

	return newIPSet(ips), nil
}

func (b *Bootstrap) resolveUpstream(ctx context.Context, r Resolver, host string) ([]net.IP, error) {
	// Use system resolver if no bootstrap is configured
	if b.resolver == nil {
		ctx, cancel := context.WithTimeout(ctx, b.timeout)
		defer cancel()

		return b.systemResolver.LookupIP(ctx, b.connectIPVersion.Net(), host)
	}

	if ips, ok := b.bootstraped[r]; ok {
		// Special path for bootstraped upstreams to avoid infinite recursion
		return ips, nil
	}

	return b.resolve(ctx, host, b.connectIPVersion.QTypes())
}

// NewHTTPTransport returns a new http.Transport that uses b to resolve hostnames
func (b *Bootstrap) NewHTTPTransport() *http.Transport {
	if b.resolver == nil {
		return &http.Transport{
			DialContext: b.dialer.DialContext,
		}
	}

	return &http.Transport{
		DialContext: b.dialContext,
	}
}

func (b *Bootstrap) dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	logger := b.log.WithField("network", network).WithField("addr", addr)

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		logger.Errorf("dial error: %s", err)

		return nil, err
	}

	var qTypes []dns.Type

	switch {
	case b.connectIPVersion != config.IPVersionDual: // ignore `network` if a specific version is configured
		qTypes = b.connectIPVersion.QTypes()
	case strings.HasSuffix(network, "4"):
		qTypes = config.IPVersionV4.QTypes()
	case strings.HasSuffix(network, "6"):
		qTypes = config.IPVersionV6.QTypes()
	default:
		qTypes = config.IPVersionDual.QTypes()
	}

	// Resolve the host with the bootstrap DNS
	ips, err := b.resolve(ctx, host, qTypes)
	if err != nil {
		logger.Errorf("resolve error: %s", err)

		return nil, err
	}

	ip := ips[rand.Intn(len(ips))] //nolint:gosec

	logger.WithField("ip", ip).Tracef("dialing %s", host)

	// Use the standard dialer to actually connect
	addrWithIP := net.JoinHostPort(ip.String(), port)

	return b.dialer.DialContext(ctx, network, addrWithIP)
}

func (b *Bootstrap) resolve(ctx context.Context, hostname string, qTypes []dns.Type) (ips []net.IP, err error) {
	ips = make([]net.IP, 0, len(qTypes))

	for _, qType := range qTypes {
		qIPs, qErr := b.resolveType(ctx, hostname, qType)
		if qErr != nil {
			err = multierror.Append(err, qErr)

			continue
		}

		ips = append(ips, qIPs...)
	}

	if err == nil && len(ips) == 0 {
		return nil, fmt.Errorf("no such host %s", hostname)
	}

	return
}

func (b *Bootstrap) resolveType(ctx context.Context, hostname string, qType dns.Type) (ips []net.IP, err error) {
	if ip := net.ParseIP(hostname); ip != nil {
		return []net.IP{ip}, nil
	}

	req := model.Request{
		Req: util.NewMsgWithQuestion(hostname, qType),
		Log: b.log,
	}

	rsp, err := b.resolver.Resolve(ctx, &req)
	if err != nil {
		return nil, err
	}

	if rsp.Res.Rcode != dns.RcodeSuccess {
		return nil, nil
	}

	ips = make([]net.IP, 0, len(rsp.Res.Answer))

	for _, a := range rsp.Res.Answer {
		switch rr := a.(type) {
		case *dns.A:
			ips = append(ips, rr.A)
		case *dns.AAAA:
			ips = append(ips, rr.AAAA)
		}
	}

	return ips, nil
}

// map of bootstraped resolvers their hardcoded IPs
type bootstrapedResolvers map[Resolver][]net.IP

func newBootstrapedResolvers(
	b *Bootstrap, cfg config.BootstrapDNSConfig, upstreamsCfg config.Upstreams,
) (bootstrapedResolvers, error) {
	upstreamIPs := make(bootstrapedResolvers, len(cfg))

	var multiErr *multierror.Error

	for i, upstreamCfg := range cfg {
		i := i + 1 // user visible index should start at 1

		upstream := upstreamCfg.Upstream

		if upstream.IsDefault() {
			multiErr = multierror.Append(
				multiErr,
				fmt.Errorf("item %d: upstream not configured (ips=%v)", i, upstreamCfg.IPs),
			)

			continue
		}

		var ips []net.IP

		if ip := net.ParseIP(upstream.Host); ip != nil {
			ips = append(ips, ip)
		} else if upstream.Net == config.NetProtocolTcpUdp {
			multiErr = multierror.Append(
				multiErr,
				fmt.Errorf("item %d: '%s': protocol %s must use IP instead of hostname", i, upstream, upstream.Net),
			)

			continue
		}

		ips = append(ips, upstreamCfg.IPs...)

		if len(ips) == 0 {
			multiErr = multierror.Append(multiErr, fmt.Errorf("item %d: '%s': no IPs configured", i, upstream))

			continue
		}

		resolver := newUpstreamResolverUnchecked(newUpstreamConfig(upstream, upstreamsCfg), b)

		upstreamIPs[resolver] = ips
	}

	if multiErr != nil {
		return nil, fmt.Errorf("invalid bootstrapDns configuration: %w", multiErr)
	}

	return upstreamIPs, nil
}

func (br bootstrapedResolvers) Resolvers() []Resolver {
	return maps.Keys(br)
}

type IPSet struct {
	values []net.IP
	index  uint32
}

func newIPSet(ips []net.IP) *IPSet {
	return &IPSet{values: ips}
}

func (ips *IPSet) Current() net.IP {
	idx := atomic.LoadUint32(&ips.index)

	return ips.values[idx]
}

func (ips *IPSet) Next() {
	oldIP := ips.index
	newIP := uint32(int(ips.index+1) % len(ips.values))

	// We don't care about the result: if the call fails,
	// it means the value was incremented by another goroutine
	_ = atomic.CompareAndSwapUint32(&ips.index, oldIP, newIP)
}
