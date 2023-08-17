package resolver

import (
	"fmt"
	"strings"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/log"
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"
	"github.com/sirupsen/logrus"
)

const (
	upstreamTreeResolverType = "upstream_tree"
)

type UpstreamTreeResolver struct {
	configurable[*config.UpstreamsConfig]
	typed

	branches map[string]Resolver
}

func NewUpstreamTreeResolver(cfg config.UpstreamsConfig, branches map[string]Resolver) (Resolver, error) {
	if len(cfg.Groups[upstreamDefaultCfgName]) == 0 {
		return nil, fmt.Errorf("no external DNS resolvers configured as default upstream resolvers. "+
			"Please configure at least one under '%s' configuration name", upstreamDefaultCfgName)
	}

	if len(branches) != len(cfg.Groups) {
		return nil, fmt.Errorf("amount of passed in branches (%d) does not match amount of configured upstream groups (%d)",
			len(branches), len(cfg.Groups))
	}

	if len(branches) == 1 {
		for _, r := range branches {
			return r, nil
		}
	}

	// return resolver that forwards request to specific resolver branch depending on the client
	r := UpstreamTreeResolver{
		configurable: withConfig(&cfg),
		typed:        withType(upstreamTreeResolverType),

		branches: branches,
	}

	return &r, nil
}

func (r *UpstreamTreeResolver) Name() string {
	return r.String()
}

func (r *UpstreamTreeResolver) String() string {
	result := make([]string, 0, len(r.branches))

	for group, res := range r.branches {
		result = append(result, fmt.Sprintf("%s (%s)", group, res.Type()))
	}

	return fmt.Sprintf("%s upstreams %q", upstreamTreeResolverType, strings.Join(result, ", "))
}

func (r *UpstreamTreeResolver) Resolve(request *model.Request) (*model.Response, error) {
	logger := log.WithPrefix(request.Log, upstreamTreeResolverType)

	group := r.upstreamGroupByClient(request)

	// delegate request to group resolver
	logger.WithField("resolver", fmt.Sprintf("%s (%s)", group, r.branches[group].Type())).Debug("delegating to resolver")

	return r.branches[group].Resolve(request)
}

func (r *UpstreamTreeResolver) upstreamGroupByClient(request *model.Request) string {
	groups := []string{}
	clientIP := request.ClientIP.String()

	// try IP
	if _, exists := r.branches[clientIP]; exists {
		return clientIP
	}

	// try client names
	for _, name := range request.ClientNames {
		for group := range r.branches {
			if util.ClientNameMatchesGroupName(group, name) {
				groups = append(groups, group)
			}
		}
	}

	// try CIDR (only if no client name matched)
	if len(groups) == 0 {
		for cidr := range r.branches {
			if util.CidrContainsIP(cidr, request.ClientIP) {
				groups = append(groups, cidr)
			}
		}
	}

	if len(groups) > 0 {
		if len(groups) > 1 {
			r.log().WithFields(logrus.Fields{
				"clientNames": request.ClientNames,
				"clientIP":    clientIP,
				"groups":      groups,
			}).Warn("client matches multiple groups")
		}

		return groups[0]
	}

	return upstreamDefaultCfgName
}
