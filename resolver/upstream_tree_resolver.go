package resolver

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"
	"github.com/sirupsen/logrus"
)

const (
	upstreamTreeResolverType = "upstream_tree"
)

type UpstreamTreeResolver struct {
	configurable[*config.Upstreams]
	typed

	branches map[string]Resolver
}

func NewUpstreamTreeResolver(ctx context.Context, cfg config.Upstreams, bootstrap *Bootstrap) (Resolver, error) {
	if len(cfg.Groups[upstreamDefaultCfgName]) == 0 {
		return nil, fmt.Errorf("no external DNS resolvers configured as default upstream resolvers. "+
			"Please configure at least one under '%s' configuration name", upstreamDefaultCfgName)
	}

	branches, err := createUpstreamBranches(ctx, cfg, bootstrap)
	if err != nil {
		return nil, err
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

func createUpstreamBranches(
	ctx context.Context, cfg config.Upstreams, bootstrap *Bootstrap,
) (map[string]Resolver, error) {
	branches := make(map[string]Resolver, len(cfg.Groups))
	errs := make([]error, 0, len(cfg.Groups))

	for group, upstreams := range cfg.Groups {
		var (
			upstream Resolver
			err      error
		)

		groupConfig := config.NewUpstreamGroup(group, cfg, upstreams)

		switch cfg.Strategy {
		case config.UpstreamStrategyParallelBest:
			fallthrough
		case config.UpstreamStrategyRandom:
			upstream, err = NewParallelBestResolver(ctx, groupConfig, bootstrap)
		case config.UpstreamStrategyStrict:
			upstream, err = NewStrictResolver(ctx, groupConfig, bootstrap)
		}

		if err != nil {
			errs = append(errs, fmt.Errorf("group %s: %w", group, err))

			continue
		}

		branches[group] = upstream
	}

	if len(errs) != 0 {
		return nil, errors.Join(errs...)
	}

	return branches, nil
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

func (r *UpstreamTreeResolver) Resolve(ctx context.Context, request *model.Request) (*model.Response, error) {
	ctx, logger := r.log(ctx)

	group := r.upstreamGroupByClient(logger, request)

	// delegate request to group resolver
	logger.WithField("resolver", fmt.Sprintf("%s (%s)", group, r.branches[group].Type())).Debug("delegating to resolver")

	return r.branches[group].Resolve(ctx, request)
}

func (r *UpstreamTreeResolver) upstreamGroupByClient(logger *logrus.Entry, request *model.Request) string {
	groups := make([]string, 0, len(r.branches))
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
			logger.WithFields(logrus.Fields{
				"clientNames": request.ClientNames,
				"clientIP":    clientIP,
				"groups":      groups,
			}).Warn("client matches multiple groups")
		}

		return groups[0]
	}

	return upstreamDefaultCfgName
}
