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
)

// nolint:gochecknoglobals
var (
	v4v6QTypes = []dns.Type{dns.Type(dns.TypeA), dns.Type(dns.TypeAAAA)}
)

// Bootstrap allows resolving hostnames using the configured bootstrap DNS.
type Bootstrap struct {
	log *logrus.Entry

	resolver    Resolver
	upstream    Resolver // the upstream that's part of the above resolver
	upstreamIPs []net.IP // IPs for b.upstream

	systemResolver *net.Resolver
}

// NewBootstrap creates and returns a new Bootstrap.
// Internally, it uses a CachingResolver and an UpstreamResolver.
func NewBootstrap(cfg *config.Config) (b *Bootstrap, err error) {
	upstream := cfg.BootstrapDNS.Upstream
	log := log.PrefixedLog("bootstrap")

	var ips []net.IP

	switch {
	case upstream.IsDefault():
		log.Infof("bootstrapDns is not configured, will use system resolver")
	case upstream.Net == config.NetProtocolTcpUdp:
		ip := net.ParseIP(upstream.Host)
		if ip == nil {
			return nil, fmt.Errorf("bootstrapDns uses %s but is not an IP", upstream.Net)
		}

		ips = append(ips, ip)
	default:
		ips = cfg.BootstrapDNS.IPs
		if len(ips) == 0 {
			return nil, fmt.Errorf("bootstrapDns.IPs is required when upstream uses %s", upstream.Net)
		}
	}

	// Create b in multiple steps: Bootstrap and UpstreamResolver have a cyclic dependency
	// This also prevents the GC to clean up these two structs, but is not currently an
	// issue since they stay allocated until the process terminates
	b = &Bootstrap{
		log:            log,
		upstreamIPs:    ips,
		systemResolver: net.DefaultResolver, // allow replacing it during tests
	}

	if upstream.IsDefault() {
		return b, nil
	}

	b.upstream = newUpstreamResolverUnchecked(upstream, b)

	b.resolver = Chain(
		NewFilteringResolver(cfg.Filtering),
		NewCachingResolver(cfg.Caching, nil),
		b.upstream,
	)

	return b, nil
}

func (b *Bootstrap) UpstreamIPs(r *UpstreamResolver) (*IPSet, error) {
	ips, err := b.resolveUpstream(r, r.upstream.Host)
	if err != nil {
		return nil, err
	}

	return &IPSet{values: ips}, nil
}

func (b *Bootstrap) resolveUpstream(r Resolver, host string) ([]net.IP, error) {
	// Use system resolver if no bootstrap is configured
	if b.resolver == nil {
		filteredQTypes := config.GetConfig().Filtering.QueryTypes

		network := "ip"
		if filteredQTypes.Contains(dns.Type(dns.TypeAAAA)) {
			network = "ip4"
		} else if filteredQTypes.Contains(dns.Type(dns.TypeA)) {
			network = "ip6"
		}

		ctx := context.Background()

		timeout := config.GetConfig().UpstreamTimeout
		if timeout != 0 {
			var cancel context.CancelFunc

			ctx, cancel = context.WithTimeout(context.Background(), time.Duration(timeout))
			defer cancel()
		}

		return b.systemResolver.LookupIP(ctx, network, host)
	}

	if r == b.upstream {
		// Special path for b.upstream to avoid infinite recursion
		return b.upstreamIPs, nil
	}

	return b.resolve(host, v4v6QTypes)
}

// NewHTTPTransport returns a new http.Transport that uses b to resolve hostnames
func (b *Bootstrap) NewHTTPTransport() *http.Transport {
	if b.resolver == nil {
		return &http.Transport{}
	}

	dialer := net.Dialer{}

	return &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			log := b.log.WithField("network", network).WithField("addr", addr)

			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				log.Errorf("dial error: %s", err)

				return nil, err
			}

			filteredQTypes := config.GetConfig().Filtering.QueryTypes

			var qTypes []dns.Type

			switch {
			case strings.HasSuffix(network, "4") || filteredQTypes.Contains(dns.Type(dns.TypeAAAA)):
				qTypes = []dns.Type{dns.Type(dns.TypeA)}
			case strings.HasSuffix(network, "6") || filteredQTypes.Contains(dns.Type(dns.TypeA)):
				qTypes = []dns.Type{dns.Type(dns.TypeAAAA)}
			default:
				qTypes = v4v6QTypes
			}

			// Resolve the host with the bootstrap DNS
			ips, err := b.resolve(host, qTypes)
			if err != nil {
				log.Errorf("resolve error: %s", err)

				return nil, err
			}

			ip := ips[rand.Intn(len(ips))] // nolint:gosec

			log.WithField("ip", ip).Tracef("dialing %s", host)

			// Use the standard dialer to actually connect
			addrWithIP := net.JoinHostPort(ip.String(), port)

			return dialer.DialContext(ctx, network, addrWithIP)
		},
	}
}

func (b *Bootstrap) resolve(hostname string, qTypes []dns.Type) (ips []net.IP, err error) {
	ips = make([]net.IP, 0, len(qTypes))

	for _, qType := range qTypes {
		qIPs, qErr := b.resolveType(hostname, qType)
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

func (b *Bootstrap) resolveType(hostname string, qType dns.Type) (ips []net.IP, err error) {
	if ip := net.ParseIP(hostname); ip != nil {
		return []net.IP{ip}, nil
	}

	req := model.Request{
		Req: util.NewMsgWithQuestion(hostname, qType),
		Log: b.log,
	}

	rsp, err := b.resolver.Resolve(&req)
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

type IPSet struct {
	values []net.IP
	index  uint32
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
