package resolver

import (
	"blocky/config"
	"blocky/util"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// UpstreamResolver sends request to external DNS server
type UpstreamResolver struct {
	NextResolver
	client   *dns.Client
	upstream string
}

func NewUpstreamResolver(upstream config.Upstream) Resolver {
	client := new(dns.Client)
	client.Net = upstream.Net

	return &UpstreamResolver{
		client:   client,
		upstream: net.JoinHostPort(upstream.Host, strconv.Itoa(int(upstream.Port)))}
}

func (r *UpstreamResolver) Configuration() (result []string) {
	return
}

func (r *UpstreamResolver) Resolve(request *Request) (response *Response, err error) {
	logger := withPrefix(request.Log, "upstream_resolver")

	attempt := 1

	var rtt time.Duration

	var resp *dns.Msg

	for attempt <= 3 {
		if resp, rtt, err = r.client.Exchange(request.Req, r.upstream); err == nil {
			logger.WithFields(logrus.Fields{
				"answer":           util.AnswerToString(resp.Answer),
				"return_code":      dns.RcodeToString[resp.Rcode],
				"upstream":         r.upstream,
				"response_time_ms": rtt.Milliseconds(),
			}).Debugf("received response from upstream")

			return &Response{Res: resp, Reason: fmt.Sprintf("RESOLVED (%s) in %d ms", r.upstream, rtt.Milliseconds())}, err
		}

		if errNet, ok := err.(net.Error); ok && (errNet.Timeout() || errNet.Temporary()) {
			logger.WithField("attempt", attempt).Debugf("Temporary network error / Timeout occurred, retrying...")
			attempt++
		} else {
			return nil, err
		}
	}

	return
}

func (r UpstreamResolver) String() string {
	return fmt.Sprintf("upstream '%s'", r.upstream)
}
