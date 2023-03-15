package resolver

import (
	"net"
	"strings"
	"time"

	"github.com/0xERR0R/blocky/cache/expirationcache"
	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/log"
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// ClientNamesResolver tries to determine client name by asking responsible DNS server via rDNS (reverse lookup)
type ClientNamesResolver struct {
	configurable[*config.ClientLookupConfig]
	NextResolver
	typed

	cache            expirationcache.ExpiringCache[[]string]
	externalResolver Resolver
}

// NewClientNamesResolver creates new resolver instance
func NewClientNamesResolver(
	cfg config.ClientLookupConfig, bootstrap *Bootstrap, shouldVerifyUpstreams bool,
) (cr *ClientNamesResolver, err error) {
	var r Resolver
	if !cfg.Upstream.IsDefault() {
		r, err = NewUpstreamResolver(cfg.Upstream, bootstrap, shouldVerifyUpstreams)
		if err != nil {
			return nil, err
		}
	}

	cr = &ClientNamesResolver{
		configurable: withConfig(&cfg),
		typed:        withType("client_names"),

		cache:            expirationcache.NewCache(expirationcache.WithCleanUpInterval[[]string](time.Hour)),
		externalResolver: r,
	}

	return
}

// LogConfig implements `config.Configurable`.
func (r *ClientNamesResolver) LogConfig(logger *logrus.Entry) {
	r.cfg.LogConfig(logger)

	logger.Infof("cache entries = %d", r.cache.TotalCount())
}

// Resolve tries to resolve the client name from the ip address
func (r *ClientNamesResolver) Resolve(request *model.Request) (*model.Response, error) {
	clientNames := r.getClientNames(request)

	request.ClientNames = clientNames
	request.Log = request.Log.WithField("client_names", strings.Join(clientNames, "; "))

	return r.next.Resolve(request)
}

// returns names of client
func (r *ClientNamesResolver) getClientNames(request *model.Request) []string {
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

	names := r.resolveClientNames(ip, log.WithPrefix(request.Log, "client_names_resolver"))

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

	return
}

// tries to resolve client name from mapping, performs reverse DNS lookup otherwise
func (r *ClientNamesResolver) resolveClientNames(ip net.IP, logger *logrus.Entry) (result []string) {
	// try client mapping first
	result = r.getNameFromIPMapping(ip, result)
	if len(result) > 0 {
		return
	}

	if r.externalResolver == nil {
		return []string{ip.String()}
	}

	reverse, _ := dns.ReverseAddr(ip.String())

	resp, err := r.externalResolver.Resolve(&model.Request{
		Req: util.NewMsgWithQuestion(reverse, dns.Type(dns.TypePTR)),
		Log: logger,
	})
	if err != nil {
		logger.Error("can't resolve client name: ", err)

		return []string{ip.String()}
	}

	clientNames := extractClientNamesFromAnswer(resp.Res.Answer, ip)

	// optional: if singleNameOrder is set, use only one name in the defined order
	if len(r.cfg.SingleNameOrder) > 0 {
		for _, i := range r.cfg.SingleNameOrder {
			if i > 0 && int(i) <= len(clientNames) {
				result = []string{clientNames[i-1]}

				break
			}
		}
	} else {
		result = clientNames
	}

	logger.WithField("client_names", strings.Join(result, "; ")).Debug("resolved client name(s) from external resolver")

	return result
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
