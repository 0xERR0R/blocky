package resolver

import (
	"blocky/config"
	"blocky/util"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/patrickmn/go-cache"
	"github.com/sirupsen/logrus"
)

// ClientNamesResolver tries to determine client name by asking responsible DNS server vie rDNS (reverse lookup)
type ClientNamesResolver struct {
	cache            *cache.Cache
	externalResolver Resolver
	singleNameOrder  []uint
	NextResolver
}

func NewClientNamesResolver(cfg config.ClientLookupConfig) ChainedResolver {
	var r Resolver
	if (config.Upstream{}) != cfg.Upstream {
		r = NewUpstreamResolver(cfg.Upstream)
	}

	return &ClientNamesResolver{
		cache:            cache.New(1*time.Hour, 1*time.Hour),
		externalResolver: r,
		singleNameOrder:  cfg.SingleNameOrder,
	}
}

func (r *ClientNamesResolver) Configuration() (result []string) {
	if r.externalResolver != nil {
		result = append(result, fmt.Sprintf("singleNameOrder = \"%v\"", r.singleNameOrder))
		result = append(result, fmt.Sprintf("externalResolver = \"%s\"", r.externalResolver))
		result = append(result, fmt.Sprintf("cache item count = %d", r.cache.ItemCount()))
	} else {
		result = []string{"deactivated, use only IP address"}
	}

	return
}

func (r *ClientNamesResolver) Resolve(request *Request) (*Response, error) {
	clientNames := r.getClientNames(request)

	request.ClientNames = clientNames
	request.Log = request.Log.WithField("client_names", strings.Join(clientNames, "; "))

	return r.next.Resolve(request)
}

// returns names of client
func (r *ClientNamesResolver) getClientNames(request *Request) []string {
	ip := request.ClientIP
	c, found := r.cache.Get(ip.String())

	if found {
		if t, ok := c.([]string); ok {
			return t
		}
	}

	names := r.resolveClientNames(ip, withPrefix(request.Log, "client_names_resolver"))
	r.cache.Set(ip.String(), names, cache.DefaultExpiration)

	return names
}

// performs reverse DNS lookup
func (r *ClientNamesResolver) resolveClientNames(ip net.IP, logger *logrus.Entry) (result []string) {
	if r.externalResolver != nil {
		reverse, err := dns.ReverseAddr(ip.String())

		if err != nil {
			logger.Warnf("can't create reverse address for %s", ip.String())
			return
		}

		resp, err := r.externalResolver.Resolve(&Request{
			Req: util.NewMsgWithQuestion(reverse, dns.TypePTR),
			Log: logger,
		})

		if err != nil {
			logger.Error("can't resolve client name: ", err)
			return []string{ip.String()}
		}

		var clientNames []string

		for _, answer := range resp.Res.Answer {
			if t, ok := answer.(*dns.PTR); ok {
				hostName := strings.TrimSuffix(t.Ptr, ".")
				clientNames = append(clientNames, hostName)
			}
		}

		if len(clientNames) == 0 {
			clientNames = []string{ip.String()}
		}

		// optional: if singleNameOrder is set, use only one name in the defined order
		if len(r.singleNameOrder) > 0 {
			for _, i := range r.singleNameOrder {
				if i > 0 && int(i) <= len(clientNames) {
					result = []string{clientNames[i-1]}
					break
				}
			}
		} else {
			result = clientNames
		}

		logger.WithField("client_names", strings.Join(result, "; ")).Debug("resolved client name(s)")
	} else {
		result = []string{ip.String()}
	}

	return result
}

// reset client name cache
func (r *ClientNamesResolver) FlushCache() {
	r.cache.Flush()
}
