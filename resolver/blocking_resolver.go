package resolver

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/0xERR0R/blocky/api"
	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/evt"
	"github.com/0xERR0R/blocky/lists"
	"github.com/0xERR0R/blocky/log"
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

func createBlockHandler(cfg config.BlockingConfig) blockHandler {
	cfgBlockType := blockTypeFromConfig(cfg)

	if cfgBlockType == "NXDOMAIN" {
		return nxDomainBlockHandler{}
	}

	blockTime := blockTTLFromConfig(cfg)

	if cfgBlockType == "ZEROIP" {
		return zeroIPBlockHandler{
			BlockTimeSec: blockTime,
		}
	}

	var ips []net.IP

	for _, part := range strings.Split(cfgBlockType, ",") {
		if ip := net.ParseIP(strings.TrimSpace(part)); ip != nil {
			ips = append(ips, ip)
		}
	}

	if len(ips) > 0 {
		return ipBlockHandler{
			destinations: ips,
			BlockTimeSec: blockTime,
			fallbackHandler: zeroIPBlockHandler{
				BlockTimeSec: blockTime,
			},
		}
	}

	log.Log().Fatalf("unknown blockType, please use one of: ZeroIP, NxDomain or specify destination IP address(es)")

	return zeroIPBlockHandler{
		BlockTimeSec: blockTime,
	}
}

type status struct {
	// true: blocking of all groups is enabled
	// false: blocking is disabled. Either all groups or only particular
	enabled        bool
	disabledGroups []string
	enableTimer    *time.Timer
	disableEnd     time.Time
}

// BlockingResolver checks request's question (domain name) against black and white lists
type BlockingResolver struct {
	NextResolver
	blacklistMatcher    *lists.ListCache
	whitelistMatcher    *lists.ListCache
	cfg                 config.BlockingConfig
	blockHandler        blockHandler
	whitelistOnlyGroups map[string]bool
	status              *status
}

// NewBlockingResolver returns a new configured instance of the resolver
func NewBlockingResolver(cfg config.BlockingConfig) ChainedResolver {
	blockHandler := createBlockHandler(cfg)
	refreshPeriod := time.Duration(cfg.RefreshPeriod)
	timeout := time.Duration(cfg.DownloadTimeout)
	blacklistMatcher := lists.NewListCache(lists.ListCacheTypeBlacklist, cfg.BlackLists, refreshPeriod, timeout)
	whitelistMatcher := lists.NewListCache(lists.ListCacheTypeWhitelist, cfg.WhiteLists, refreshPeriod, timeout)
	whitelistOnlyGroups := determineWhitelistOnlyGroups(&cfg)

	res := &BlockingResolver{
		blockHandler:        blockHandler,
		cfg:                 cfg,
		blacklistMatcher:    blacklistMatcher,
		whitelistMatcher:    whitelistMatcher,
		whitelistOnlyGroups: whitelistOnlyGroups,
		status: &status{
			enabled:     true,
			enableTimer: time.NewTimer(0),
		},
	}

	return res
}

// RefreshLists triggers the refresh of all black and white lists in the cache
func (r *BlockingResolver) RefreshLists() {
	r.blacklistMatcher.Refresh()
	r.whitelistMatcher.Refresh()
}

// nolint:prealloc
func (r *BlockingResolver) retrieveAllBlockingGroups() []string {
	groups := make(map[string]bool)

	for group := range r.cfg.BlackLists {
		groups[group] = true
	}

	var result []string
	for k := range groups {
		result = append(result, k)
	}

	result = append(result, "default")
	sort.Strings(result)

	return result
}

// EnableBlocking enables the blocking against the blacklists
func (r *BlockingResolver) EnableBlocking() {
	s := r.status
	s.enableTimer.Stop()
	s.enabled = true
	s.disabledGroups = []string{}

	evt.Bus().Publish(evt.BlockingEnabledEvent, true)
}

// DisableBlocking deactivates the blocking for a particular duration (or forever if 0).
func (r *BlockingResolver) DisableBlocking(duration time.Duration, disableGroups []string) error {
	s := r.status
	s.enableTimer.Stop()
	s.enabled = false
	allBlockingGroups := r.retrieveAllBlockingGroups()

	if len(disableGroups) == 0 {
		s.disabledGroups = allBlockingGroups
	} else {
		for _, g := range disableGroups {
			i := sort.SearchStrings(allBlockingGroups, g)
			if !(i < len(allBlockingGroups) && allBlockingGroups[i] == g) {
				return fmt.Errorf("group '%s' is unknown", g)
			}
		}
		s.disabledGroups = disableGroups
	}

	evt.Bus().Publish(evt.BlockingEnabledEvent, false)

	s.disableEnd = time.Now().Add(duration)

	if duration == 0 {
		log.Log().Infof("disable blocking for group(s) '%s'", strings.Join(s.disabledGroups, "; "))
	} else {
		log.Log().Infof("disable blocking for %s for group(s) '%s'", duration, strings.Join(s.disabledGroups, "; "))
		s.enableTimer = time.AfterFunc(duration, func() {
			r.EnableBlocking()
			log.Log().Info("blocking enabled again")
		})
	}

	return nil
}

// BlockingStatus returns the current blocking status
func (r *BlockingResolver) BlockingStatus() api.BlockingStatus {
	var autoEnableDuration time.Duration
	if !r.status.enabled && r.status.disableEnd.After(time.Now()) {
		autoEnableDuration = time.Until(r.status.disableEnd)
	}

	return api.BlockingStatus{
		Enabled:         r.status.enabled,
		DisabledGroups:  r.status.disabledGroups,
		AutoEnableInSec: uint(autoEnableDuration.Seconds()),
	}
}

// returns groups, which have only whitelist entries
func determineWhitelistOnlyGroups(cfg *config.BlockingConfig) (result map[string]bool) {
	result = make(map[string]bool)

	for g, links := range cfg.WhiteLists {
		if len(links) > 0 {
			if _, found := cfg.BlackLists[g]; !found {
				result[g] = true
			}
		}
	}

	return
}

// sets answer and/or return code for DNS response, if request should be blocked
func (r *BlockingResolver) handleBlocked(logger *logrus.Entry,
	request *model.Request, question dns.Question, reason string) (*model.Response, error) {
	response := new(dns.Msg)
	response.SetReply(request.Req)

	r.blockHandler.handleBlock(question, response)

	logger.Debugf("blocking request '%s'", reason)

	return &model.Response{Res: response, RType: model.ResponseTypeBLOCKED, Reason: reason}, nil
}

// Configuration returns the current resolver configuration
func (r *BlockingResolver) Configuration() (result []string) {
	if len(r.cfg.ClientGroupsBlock) > 0 {
		result = append(result, "clientGroupsBlock")
		for key, val := range r.cfg.ClientGroupsBlock {
			result = append(result, fmt.Sprintf("  %s = \"%s\"", key, strings.Join(val, ";")))
		}

		blockType := blockTypeFromConfig(r.cfg)
		result = append(result, fmt.Sprintf("blockType = \"%s\"", blockType))

		if blockType != "NXDOMAIN" {
			blockTime := blockTTLFromConfig(r.cfg)
			result = append(result, fmt.Sprintf("blockTTL = %d", blockTime))
		}

		result = append(result, "blacklist:")
		for _, c := range r.blacklistMatcher.Configuration() {
			result = append(result, fmt.Sprintf("  %s", c))
		}

		result = append(result, "whitelist:")
		for _, c := range r.whitelistMatcher.Configuration() {
			result = append(result, fmt.Sprintf("  %s", c))
		}
	} else {
		result = []string{"deactivated"}
	}

	return
}

func (r *BlockingResolver) hasWhiteListOnlyAllowed(groupsToCheck []string) bool {
	for _, group := range groupsToCheck {
		if _, found := r.whitelistOnlyGroups[group]; found {
			return true
		}
	}

	return false
}

func (r *BlockingResolver) handleBlacklist(groupsToCheck []string,
	request *model.Request, logger *logrus.Entry) (*model.Response, error) {
	logger.WithField("groupsToCheck", strings.Join(groupsToCheck, "; ")).Debug("checking groups for request")
	whitelistOnlyAllowed := r.hasWhiteListOnlyAllowed(groupsToCheck)

	for _, question := range request.Req.Question {
		domain := util.ExtractDomain(question)
		logger := logger.WithField("domain", domain)

		if whitelisted, group := r.matches(groupsToCheck, r.whitelistMatcher, domain); whitelisted {
			logger.WithField("group", group).Debugf("domain is whitelisted")
			return r.next.Resolve(request)
		}

		if whitelistOnlyAllowed {
			return r.handleBlocked(logger, request, question, "BLOCKED (WHITELIST ONLY)")
		}

		if blocked, group := r.matches(groupsToCheck, r.blacklistMatcher, domain); blocked {
			return r.handleBlocked(logger, request, question, fmt.Sprintf("BLOCKED (%s)", group))
		}
	}

	return nil, nil
}

// Resolve checks the query against the blacklist and delegates to next resolver if domain is not blocked
func (r *BlockingResolver) Resolve(request *model.Request) (*model.Response, error) {
	logger := withPrefix(request.Log, "blacklist_resolver")
	groupsToCheck := r.groupsToCheckForClient(request)

	if len(groupsToCheck) > 0 {
		resp, err := r.handleBlacklist(groupsToCheck, request, logger)
		if resp != nil || err != nil {
			return resp, err
		}
	}

	respFromNext, err := r.next.Resolve(request)

	if err == nil && len(groupsToCheck) > 0 && respFromNext.Res != nil {
		for _, rr := range respFromNext.Res.Answer {
			entryToCheck, tName := extractEntryToCheckFromResponse(rr)
			if len(entryToCheck) > 0 {
				logger := logger.WithField("response_entry", entryToCheck)

				if whitelisted, group := r.matches(groupsToCheck, r.whitelistMatcher, entryToCheck); whitelisted {
					logger.WithField("group", group).Debugf("%s is whitelisted", tName)
				} else if blocked, group := r.matches(groupsToCheck, r.blacklistMatcher, entryToCheck); blocked {
					return r.handleBlocked(logger, request, request.Req.Question[0], fmt.Sprintf("BLOCKED %s (%s)", tName, group))
				}
			}
		}
	}

	return respFromNext, err
}

func extractEntryToCheckFromResponse(rr dns.RR) (entryToCheck string, tName string) {
	switch v := rr.(type) {
	case *dns.A:
		entryToCheck = v.A.String()
		tName = "IP"
	case *dns.AAAA:
		entryToCheck = strings.ToLower(v.AAAA.String())
		tName = "IP"
	case *dns.CNAME:
		entryToCheck = util.ExtractDomainOnly(v.Target)
		tName = "CNAME"
	}

	return
}

func (r *BlockingResolver) isGroupDisabled(group string) bool {
	for _, g := range r.status.disabledGroups {
		if g == group {
			return true
		}
	}

	return false
}

// returns groups which should be checked for client's request
func (r *BlockingResolver) groupsToCheckForClient(request *model.Request) []string {
	var groups []string
	// try client names
	for _, cName := range request.ClientNames {
		for blockGroup, groupsByName := range r.cfg.ClientGroupsBlock {
			if util.ClientNameMatchesGroupName(blockGroup, cName) {
				groups = append(groups, groupsByName...)
			}
		}
	}

	// try IP
	groupsByIP, found := r.cfg.ClientGroupsBlock[request.ClientIP.String()]

	if found {
		groups = append(groups, groupsByIP...)
	}

	// try CIDR
	for cidr, groupsByCidr := range r.cfg.ClientGroupsBlock {
		if util.CidrContainsIP(cidr, request.ClientIP) {
			groups = append(groups, groupsByCidr...)
		}
	}

	if len(groups) == 0 {
		// return default
		groups = r.cfg.ClientGroupsBlock["default"]
	}

	var result []string

	for _, g := range groups {
		if !r.isGroupDisabled(g) {
			result = append(result, g)
		}
	}

	sort.Strings(result)

	return result
}

func (r *BlockingResolver) matches(groupsToCheck []string, m lists.Matcher,
	domain string) (blocked bool, group string) {
	if len(groupsToCheck) > 0 {
		found, group := m.Match(domain, groupsToCheck)
		if found {
			return true, group
		}
	}

	return false, ""
}

const defaultBlockTTL = 6 * 60 * 60
const defaultBlockType = "ZEROIP"

type blockHandler interface {
	handleBlock(question dns.Question, response *dns.Msg)
}

type zeroIPBlockHandler struct {
	BlockTimeSec uint32
}

type nxDomainBlockHandler struct {
}

type ipBlockHandler struct {
	destinations    []net.IP
	fallbackHandler blockHandler
	BlockTimeSec    uint32
}

func (b zeroIPBlockHandler) handleBlock(question dns.Question, response *dns.Msg) {
	var zeroIP net.IP

	switch question.Qtype {
	case dns.TypeAAAA:
		zeroIP = net.IPv6zero
	case dns.TypeA:
		zeroIP = net.IPv4zero
	default:
		response.Rcode = dns.RcodeNameError
		return
	}

	rr, _ := util.CreateAnswerFromQuestion(question, zeroIP, b.BlockTimeSec)

	response.Answer = append(response.Answer, rr)
}

func (b nxDomainBlockHandler) handleBlock(_ dns.Question, response *dns.Msg) {
	response.Rcode = dns.RcodeNameError
}

func (b ipBlockHandler) handleBlock(question dns.Question, response *dns.Msg) {
	for _, ip := range b.destinations {
		answer, _ := util.CreateAnswerFromQuestion(question, ip, b.BlockTimeSec)

		if (question.Qtype == dns.TypeAAAA && ip.To4() == nil) || (question.Qtype == dns.TypeA && ip.To4() != nil) {
			response.Answer = append(response.Answer, answer)
		}
	}

	if len(response.Answer) == 0 {
		// use fallback
		b.fallbackHandler.handleBlock(question, response)
	}
}

func blockTTLFromConfig(cfg config.BlockingConfig) uint32 {
	if cfg.BlockTTL <= 0 {
		return defaultBlockTTL
	}

	return uint32(time.Duration(cfg.BlockTTL).Seconds())
}

func blockTypeFromConfig(cfg config.BlockingConfig) string {
	if cfgBlockType := strings.TrimSpace(strings.ToUpper(cfg.BlockType)); cfgBlockType != "" {
		return cfgBlockType
	}

	return defaultBlockType
}
