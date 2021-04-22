package resolver

import (
	"blocky/api"
	"blocky/config"
	"blocky/evt"
	"blocky/lists"
	"blocky/util"
	"fmt"
	"net"
	"reflect"
	"sort"
	"strings"
	"time"

	"blocky/log"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

func createBlockHandler(cfg config.BlockingConfig) blockHandler {
	cfgBlockType := strings.TrimSpace(strings.ToUpper(cfg.BlockType))
	if cfgBlockType == "" || cfgBlockType == "ZEROIP" {
		return zeroIPBlockHandler{}
	}

	if cfgBlockType == "NXDOMAIN" {
		return nxDomainBlockHandler{}
	}

	var ips []net.IP

	for _, part := range strings.Split(cfgBlockType, ",") {
		if ip := net.ParseIP(strings.TrimSpace(part)); ip != nil {
			ips = append(ips, ip)
		}
	}

	if len(ips) > 0 {
		return ipBlockHandler{
			destinations:    ips,
			fallbackHandler: zeroIPBlockHandler{},
		}
	}

	log.Log().Fatalf("unknown blockType, please use one of: ZeroIP, NxDomain or specify destination IP address(es)")

	return zeroIPBlockHandler{}
}

type status struct {
	enabled     bool
	enableTimer *time.Timer
	disableEnd  time.Time
}

// BlockingResolver checks request's question (domain name) against black and white lists
type BlockingResolver struct {
	NextResolver
	blacklistMatcher    *lists.ListCache
	whitelistMatcher    *lists.ListCache
	cfg                 config.BlockingConfig
	blockHandler        blockHandler
	whitelistOnlyGroups []string
	status              *status
}

// NewBlockingResolver returns a new configured instance of the resolver
func NewBlockingResolver(cfg config.BlockingConfig) ChainedResolver {
	blockHandler := createBlockHandler(cfg)
	blacklistMatcher := lists.NewListCache(lists.BLACKLIST, cfg.BlackLists, cfg.RefreshPeriod)
	whitelistMatcher := lists.NewListCache(lists.WHITELIST, cfg.WhiteLists, cfg.RefreshPeriod)
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

// EnableBlocking enables the blocking against the blacklists
func (r *BlockingResolver) EnableBlocking() {
	s := r.status
	s.enableTimer.Stop()
	s.enabled = true

	evt.Bus().Publish(evt.BlockingEnabledEvent, true)
}

// DisableBlocking deaktivates the blocking for a particular duration (or forever if 0)
func (r *BlockingResolver) DisableBlocking(duration time.Duration) {
	s := r.status
	s.enableTimer.Stop()
	s.enabled = false

	evt.Bus().Publish(evt.BlockingEnabledEvent, false)

	s.disableEnd = time.Now().Add(duration)

	if duration == 0 {
		log.Log().Info("disable blocking")
	} else {
		log.Log().Infof("disable blocking for %s", duration)
		s.enableTimer = time.AfterFunc(duration, func() {
			r.EnableBlocking()
			log.Log().Info("blocking enabled again")
		})
	}
}

// BlockingStatus returns the current blocking status
func (r *BlockingResolver) BlockingStatus() api.BlockingStatus {
	var autoEnableDuration time.Duration
	if !r.status.enabled && r.status.disableEnd.After(time.Now()) {
		autoEnableDuration = time.Until(r.status.disableEnd)
	}

	return api.BlockingStatus{
		Enabled:         r.status.enabled,
		AutoEnableInSec: uint(autoEnableDuration.Seconds()),
	}
}

// returns groups, which have only whitelist entries
func determineWhitelistOnlyGroups(cfg *config.BlockingConfig) (result []string) {
	for g, links := range cfg.WhiteLists {
		if len(links) > 0 {
			if _, found := cfg.BlackLists[g]; !found {
				result = append(result, g)
			}
		}
	}

	sort.Strings(result)

	return
}

// sets answer and/or return code for DNS response, if request should be blocked
func (r *BlockingResolver) handleBlocked(logger *logrus.Entry,
	request *Request, question dns.Question, reason string) (*Response, error) {
	response := new(dns.Msg)
	response.SetReply(request.Req)

	r.blockHandler.handleBlock(question, response)

	logger.Debugf("blocking request '%s'", reason)

	return &Response{Res: response, RType: BLOCKED, Reason: reason}, nil
}

// Configuration returns the current resolver configuration
func (r *BlockingResolver) Configuration() (result []string) {
	if len(r.cfg.ClientGroupsBlock) > 0 {
		result = append(result, "clientGroupsBlock")
		for key, val := range r.cfg.ClientGroupsBlock {
			result = append(result, fmt.Sprintf("  %s = \"%s\"", key, strings.Join(val, ";")))
		}

		result = append(result, fmt.Sprintf("blockType = \"%s\"", r.cfg.BlockType))

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

func (r *BlockingResolver) handleBlacklist(groupsToCheck []string,
	request *Request, logger *logrus.Entry) (*Response, error) {
	logger.WithField("groupsToCheck", strings.Join(groupsToCheck, "; ")).Debug("checking groups for request")
	whitelistOnlyAllowed := reflect.DeepEqual(groupsToCheck, r.whitelistOnlyGroups)

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
func (r *BlockingResolver) Resolve(request *Request) (*Response, error) {
	logger := withPrefix(request.Log, "blacklist_resolver")
	groupsToCheck := r.groupsToCheckForClient(request)

	if r.status.enabled && len(groupsToCheck) > 0 {
		resp, err := r.handleBlacklist(groupsToCheck, request, logger)
		if resp != nil || err != nil {
			return resp, err
		}
	}

	respFromNext, err := r.next.Resolve(request)

	if err == nil && r.status.enabled && len(groupsToCheck) > 0 && respFromNext.Res != nil {
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

// returns groups which should be checked for client's request
func (r *BlockingResolver) groupsToCheckForClient(request *Request) (groups []string) {
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
		if !found {
			// return default
			groups = r.cfg.ClientGroupsBlock["default"]
		}
	}

	sort.Strings(groups)

	return groups
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

const blockTTL = 6 * 60 * 60

type blockHandler interface {
	handleBlock(question dns.Question, response *dns.Msg)
}

type zeroIPBlockHandler struct {
}

type nxDomainBlockHandler struct {
}

type ipBlockHandler struct {
	destinations    []net.IP
	fallbackHandler blockHandler
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

	rr, _ := util.CreateAnswerFromQuestion(question, zeroIP, blockTTL)

	response.Answer = append(response.Answer, rr)
}

func (b nxDomainBlockHandler) handleBlock(_ dns.Question, response *dns.Msg) {
	response.Rcode = dns.RcodeNameError
}

func (b ipBlockHandler) handleBlock(question dns.Question, response *dns.Msg) {
	for _, ip := range b.destinations {
		answer, _ := util.CreateAnswerFromQuestion(question, ip, blockTTL)

		if (question.Qtype == dns.TypeAAAA && ip.To4() == nil) || (question.Qtype == dns.TypeA && ip.To4() != nil) {
			response.Answer = append(response.Answer, answer)
		}
	}

	if len(response.Answer) == 0 {
		// use fallback
		b.fallbackHandler.handleBlock(question, response)
	}
}
