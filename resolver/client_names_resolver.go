package resolver

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/0xERR0R/blocky/cache"
	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/log"
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"
	expirationcache "github.com/0xERR0R/expiration-cache"
	"github.com/miekg/dns"
)

// reverseLookuper resolves host names for an IP from local, in-memory data only
// (e.g. hosts files or custom DNS). It performs no network I/O.
type reverseLookuper interface {
	LookupReverse(ip net.IP) []string
}

// ClientNamesResolver tries to determine client name by asking responsible DNS server via rDNS (reverse lookup)
type ClientNamesResolver struct {
	configurable[*config.ClientLookup]
	NextResolver
	typed

	cache            cache.ExpiringCache[[]string]
	externalResolver Resolver
	reverseLookupers []reverseLookuper
}

// NewClientNamesResolver creates new resolver instance.
//
// localReverseLookupers are consulted, in order, for in-memory reverse (IP -> name)
// resolution before falling back to the configured rDNS upstream.
func NewClientNamesResolver(ctx context.Context,
	cfg config.ClientLookup, upstreamsCfg config.Upstreams, bootstrap *Bootstrap,
	localReverseLookupers ...reverseLookuper,
) (cr *ClientNamesResolver, err error) {
	var r Resolver
	if !cfg.Upstream.IsDefault() {
		r, err = NewUpstreamResolver(ctx, newUpstreamConfig(cfg.Upstream, upstreamsCfg), bootstrap)
		if err != nil {
			return nil, fmt.Errorf("failed to create upstream resolver for client names lookup: %w", err)
		}
	}

	cr = &ClientNamesResolver{
		configurable: withConfig(&cfg),
		typed:        withType("client_names"),

		cache: expirationcache.NewCache[[]string](ctx, expirationcache.Options{
			CleanupInterval: time.Hour,
			Shards:          cache.ShardCount(),
		}),
		externalResolver: r,
		reverseLookupers: localReverseLookupers,
	}

	return cr, err
}

// LogConfig implements `config.Configurable`.
func (r *ClientNamesResolver) LogConfig(logger *slog.Logger) {
	r.cfg.LogConfig(logger)

	logger.Info(fmt.Sprintf("cache entries = %d", r.cache.TotalCount()))
}

// Resolve tries to resolve the client name from the ip address
func (r *ClientNamesResolver) Resolve(ctx context.Context, request *model.Request) (*model.Response, error) {
	clientNames := r.getClientNames(ctx, request)

	request.ClientNames = clientNames
	ctx, _ = log.CtxWithFields(ctx, slog.String("client_names", strings.Join(clientNames, "; ")))

	return r.next.Resolve(ctx, request)
}

// returns names of client
func (r *ClientNamesResolver) getClientNames(ctx context.Context, request *model.Request) []string {
	if request.RequestClientID != "" {
		return []string{request.RequestClientID}
	}

	ip := request.ClientIP
	if ip == nil {
		return []string{}
	}

	c, _ := r.cache.Get(ip.String())
	if c != nil {
		// return copy here, since we can't control all usages here
		cpy := make([]string, len(*c))
		copy(cpy, *c)

		return cpy
	}

	names := r.resolveClientNames(ctx, ip)

	r.cache.Put(ip.String(), &names, time.Hour)

	return names
}

func extractClientNamesFromAnswer(answer []dns.RR, fallbackIP net.IP) (clientNames []string) {
	for _, answer := range answer {
		if t, ok := answer.(*dns.PTR); ok {
			hostName := strings.TrimSuffix(t.Ptr, ".")
			clientNames = append(clientNames, hostName)
		}
	}

	if len(clientNames) == 0 {
		clientNames = []string{fallbackIP.String()}
	}

	return clientNames
}

// tries to resolve client name from mapping, then from local in-memory sources,
// and performs a reverse DNS lookup against the configured upstream otherwise
func (r *ClientNamesResolver) resolveClientNames(ctx context.Context, ip net.IP) (result []string) {
	ctx, logger := r.log(ctx)

	// try client mapping first
	result = r.getNameFromIPMapping(ip, result)
	if len(result) > 0 {
		return result
	}

	// try local, in-memory reverse sources (hosts file, custom DNS) before any network lookup
	if names := r.lookupLocalReverse(ip); len(names) > 0 {
		result = applySingleNameOrder(names, r.cfg.SingleNameOrder)

		logger.DebugContext(ctx, "resolved client name(s) from local reverse lookup",
			slog.String("client_names", strings.Join(result, "; ")))

		return result
	}

	if r.externalResolver == nil {
		return []string{ip.String()}
	}

	reverse, _ := dns.ReverseAddr(ip.String())

	resp, err := r.externalResolver.Resolve(ctx, &model.Request{
		Req: util.NewMsgWithQuestion(reverse, dns.Type(dns.TypePTR)),
	})
	if err != nil {
		logger.ErrorContext(ctx, "can't resolve client name", log.AttrError(err))

		return []string{ip.String()}
	}

	clientNames := extractClientNamesFromAnswer(resp.Res.Answer, ip)
	result = applySingleNameOrder(clientNames, r.cfg.SingleNameOrder)

	logger.DebugContext(ctx, "resolved client name(s) from external resolver",
		slog.String("client_names", strings.Join(result, "; ")))

	return result
}

// lookupLocalReverse returns the first non-empty result from the configured local
// reverse lookupers (hosts file, custom DNS), or nil if none has a name for the IP.
func (r *ClientNamesResolver) lookupLocalReverse(ip net.IP) []string {
	for _, l := range r.reverseLookupers {
		if names := l.LookupReverse(ip); len(names) > 0 {
			return names
		}
	}

	return nil
}

// applySingleNameOrder reduces the resolved names to a single one following the
// configured 1-based order. If order is empty, all names are returned unchanged.
// If order is set but no configured index is in range, no name is returned.
func applySingleNameOrder(names []string, order []uint) []string {
	if len(order) == 0 {
		return names
	}

	for _, i := range order {
		if i > 0 && int(i) <= len(names) {
			return []string{names[i-1]}
		}
	}

	return nil
}

func (r *ClientNamesResolver) getNameFromIPMapping(ip net.IP, result []string) []string {
	for name, ips := range r.cfg.ClientnameIPMapping {
		for _, i := range ips {
			if ip.String() == i.String() {
				result = append(result, name)
			}
		}
	}

	return result
}

// FlushCache reset client name cache
func (r *ClientNamesResolver) FlushCache() {
	r.cache.Clear()
}
