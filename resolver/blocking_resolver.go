package resolver

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/0xERR0R/blocky/cache/expirationcache"

	"github.com/hashicorp/go-multierror"

	"github.com/0xERR0R/blocky/api"
	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/evt"
	"github.com/0xERR0R/blocky/lists"
	"github.com/0xERR0R/blocky/log"
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/redis"
	"github.com/0xERR0R/blocky/util"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

const defaultBlockingCleanUpInterval = 5 * time.Second

func createBlockHandler(cfg config.BlockingConfig) (blockHandler, error) {
	cfgBlockType := cfg.BlockType

	if strings.EqualFold(cfgBlockType, "NXDOMAIN") {
		return nxDomainBlockHandler{}, nil
	}

	blockTime := cfg.BlockTTL.SecondsU32()

	if strings.EqualFold(cfgBlockType, "ZEROIP") {
		return zeroIPBlockHandler{
			BlockTimeSec: blockTime,
		}, nil
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
		}, nil
	}

	return nil,
		fmt.Errorf("unknown blockType '%s', please use one of: ZeroIP, NxDomain or specify destination IP address(es)",
			cfgBlockType)
}

type status struct {
	// true: blocking of all groups is enabled
	// false: blocking is disabled. Either all groups or only particular
	enabled        bool
	disabledGroups []string
	enableTimer    *time.Timer
	disableEnd     time.Time
	lock           sync.RWMutex
}

// BlockingResolver checks request's question (domain name) against black and white lists
type BlockingResolver struct {
	configurable[*config.BlockingConfig]
	NextResolver
	typed

	blacklistMatcher    *lists.ListCache
	whitelistMatcher    *lists.ListCache
	blockHandler        blockHandler
	whitelistOnlyGroups map[string]bool
	status              *status
	clientGroupsBlock   map[string][]string
	redisClient         *redis.Client
	fqdnIPCache         expirationcache.ExpiringCache[[]net.IP]
}

// NewBlockingResolver returns a new configured instance of the resolver
func NewBlockingResolver(
	cfg config.BlockingConfig, redis *redis.Client, bootstrap *Bootstrap,
) (r *BlockingResolver, err error) {
	blockHandler, err := createBlockHandler(cfg)
	if err != nil {
		return nil, err
	}

	refreshPeriod := cfg.RefreshPeriod.ToDuration()
	downloader := createDownloader(cfg, bootstrap)
	blacklistMatcher, blErr := lists.NewListCache(lists.ListCacheTypeBlacklist, cfg.BlackLists,
		refreshPeriod, downloader, cfg.ProcessingConcurrency,
		(cfg.StartStrategy == config.StartStrategyTypeFast))
	whitelistMatcher, wlErr := lists.NewListCache(lists.ListCacheTypeWhitelist, cfg.WhiteLists,
		refreshPeriod, downloader, cfg.ProcessingConcurrency,
		(cfg.StartStrategy == config.StartStrategyTypeFast))
	whitelistOnlyGroups := determineWhitelistOnlyGroups(&cfg)

	err = multierror.Append(err, blErr, wlErr).ErrorOrNil()
	if err != nil && cfg.StartStrategy == config.StartStrategyTypeFailOnError {
		return nil, err
	}

	cgb := make(map[string][]string, len(cfg.ClientGroupsBlock))

	for identifier, cfgGroups := range cfg.ClientGroupsBlock {
		for _, ipart := range strings.Split(strings.ToLower(identifier), ",") {
			existingGroups, found := cgb[ipart]
			if found {
				cgb[ipart] = append(existingGroups, cfgGroups...)
			} else {
				cgb[ipart] = cfgGroups
			}
		}
	}

	res := &BlockingResolver{
		configurable: withConfig(&cfg),
		typed:        withType("blocking"),

		blockHandler:        blockHandler,
		blacklistMatcher:    blacklistMatcher,
		whitelistMatcher:    whitelistMatcher,
		whitelistOnlyGroups: whitelistOnlyGroups,
		status: &status{
			enabled:     true,
			enableTimer: time.NewTimer(0),
		},
		clientGroupsBlock: cgb,
		redisClient:       redis,
	}

	if res.redisClient != nil {
		setupRedisEnabledSubscriber(res)
	}

	_ = evt.Bus().Subscribe(evt.ApplicationStarted, func(_ ...string) {
		go res.initFQDNIPCache()
	})

	return res, nil
}

func createDownloader(cfg config.BlockingConfig, bootstrap *Bootstrap) *lists.HTTPDownloader {
	return lists.NewDownloader(
		lists.WithTimeout(cfg.DownloadTimeout.ToDuration()),
		lists.WithAttempts(cfg.DownloadAttempts),
		lists.WithCooldown(cfg.DownloadCooldown.ToDuration()),
		lists.WithTransport(bootstrap.NewHTTPTransport()),
	)
}

func setupRedisEnabledSubscriber(c *BlockingResolver) {
	go func() {
		for em := range c.redisClient.EnabledChannel {
			if em != nil {
				c.log().Debug("Received state from redis: ", em)

				if em.State {
					c.internalEnableBlocking()
				} else {
					err := c.internalDisableBlocking(em.Duration, em.Groups)
					if err != nil {
						c.log().Warn("Blocking couldn't be disabled:", err)
					}
				}
			}
		}
	}()
}

// RefreshLists triggers the refresh of all black and white lists in the cache
func (r *BlockingResolver) RefreshLists() {
	r.blacklistMatcher.Refresh()
	r.whitelistMatcher.Refresh()
}

//nolint:prealloc
func (r *BlockingResolver) retrieveAllBlockingGroups() []string {
	groups := make(map[string]bool, len(r.cfg.BlackLists))

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
	r.internalEnableBlocking()

	if r.redisClient != nil {
		r.redisClient.PublishEnabled(&redis.EnabledMessage{State: true})
	}
}

func (r *BlockingResolver) internalEnableBlocking() {
	s := r.status
	s.lock.Lock()
	defer s.lock.Unlock()
	s.enableTimer.Stop()
	s.enabled = true
	s.disabledGroups = []string{}

	evt.Bus().Publish(evt.BlockingEnabledEvent, true)
}

// DisableBlocking deactivates the blocking for a particular duration (or forever if 0).
func (r *BlockingResolver) DisableBlocking(duration time.Duration, disableGroups []string) error {
	err := r.internalDisableBlocking(duration, disableGroups)
	if err == nil && r.redisClient != nil {
		r.redisClient.PublishEnabled(&redis.EnabledMessage{
			State:    false,
			Duration: duration,
			Groups:   disableGroups,
		})
	}

	return err
}

func (r *BlockingResolver) internalDisableBlocking(duration time.Duration, disableGroups []string) error {
	s := r.status
	s.lock.Lock()
	defer s.lock.Unlock()
	s.enableTimer.Stop()

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

	s.enabled = false
	evt.Bus().Publish(evt.BlockingEnabledEvent, false)

	s.disableEnd = time.Now().Add(duration)

	if duration == 0 {
		log.Log().Infof("disable blocking for group(s) '%s'", log.EscapeInput(strings.Join(s.disabledGroups, "; ")))
	} else {
		log.Log().Infof("disable blocking for %s for group(s) '%s'", duration,
			log.EscapeInput(strings.Join(s.disabledGroups, "; ")))
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

	r.status.lock.RLock()
	defer r.status.lock.RUnlock()

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
	result = make(map[string]bool, len(cfg.WhiteLists))

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
	request *model.Request, question dns.Question, reason string,
) (*model.Response, error) {
	response := new(dns.Msg)
	response.SetReply(request.Req)

	r.blockHandler.handleBlock(question, response)

	logger.Debugf("blocking request '%s'", reason)

	return &model.Response{Res: response, RType: model.ResponseTypeBLOCKED, Reason: reason}, nil
}

// LogConfig implements `config.Configurable`.
func (r *BlockingResolver) LogConfig(logger *logrus.Entry) {
	r.cfg.LogConfig(logger)

	logger.Info("blacklist cache entries:")
	log.WithIndent(logger, "  ", r.blacklistMatcher.LogConfig)

	logger.Info("whitelist cache entries:")
	log.WithIndent(logger, "  ", r.whitelistMatcher.LogConfig)
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
	request *model.Request, logger *logrus.Entry,
) (bool, *model.Response, error) {
	logger.WithField("groupsToCheck", strings.Join(groupsToCheck, "; ")).Debug("checking groups for request")
	whitelistOnlyAllowed := r.hasWhiteListOnlyAllowed(groupsToCheck)

	for _, question := range request.Req.Question {
		domain := util.ExtractDomain(question)
		logger := logger.WithField("domain", domain)

		if groups := r.matches(groupsToCheck, r.whitelistMatcher, domain); len(groups) > 0 {
			logger.WithField("groups", groups).Debugf("domain is whitelisted")

			resp, err := r.next.Resolve(request)

			return true, resp, err
		}

		if whitelistOnlyAllowed {
			resp, err := r.handleBlocked(logger, request, question, "BLOCKED (WHITELIST ONLY)")

			return true, resp, err
		}

		if groups := r.matches(groupsToCheck, r.blacklistMatcher, domain); len(groups) > 0 {
			resp, err := r.handleBlocked(logger, request, question, fmt.Sprintf("BLOCKED (%s)", strings.Join(groups, ",")))

			return true, resp, err
		}
	}

	return false, nil, nil
}

// Resolve checks the query against the blacklist and delegates to next resolver if domain is not blocked
func (r *BlockingResolver) Resolve(request *model.Request) (*model.Response, error) {
	logger := log.WithPrefix(request.Log, "blacklist_resolver")
	groupsToCheck := r.groupsToCheckForClient(request)

	if len(groupsToCheck) > 0 {
		handled, resp, err := r.handleBlacklist(groupsToCheck, request, logger)
		if handled {
			return resp, err
		}
	}

	respFromNext, err := r.next.Resolve(request)

	if err == nil && len(groupsToCheck) > 0 && respFromNext.Res != nil {
		for _, rr := range respFromNext.Res.Answer {
			entryToCheck, tName := extractEntryToCheckFromResponse(rr)
			if len(entryToCheck) > 0 {
				logger := logger.WithField("response_entry", entryToCheck)

				if groups := r.matches(groupsToCheck, r.whitelistMatcher, entryToCheck); len(groups) > 0 {
					logger.WithField("groups", groups).Debugf("%s is whitelisted", tName)
				} else if groups := r.matches(groupsToCheck, r.blacklistMatcher, entryToCheck); len(groups) > 0 {
					return r.handleBlocked(logger, request, request.Req.Question[0], fmt.Sprintf("BLOCKED %s (%s)", tName,
						strings.Join(groups, ",")))
				}
			}
		}
	}

	return respFromNext, err
}

func extractEntryToCheckFromResponse(rr dns.RR) (entryToCheck, tName string) {
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
	r.status.lock.RLock()
	defer r.status.lock.RUnlock()

	for _, g := range r.status.disabledGroups {
		if g == group {
			return true
		}
	}

	return false
}

// returns groups which should be checked for client's request
func (r *BlockingResolver) groupsToCheckForClient(request *model.Request) []string {
	r.status.lock.RLock()
	defer r.status.lock.RUnlock()

	var groups []string
	// try client names
	for _, cName := range request.ClientNames {
		for blockGroup, groupsByName := range r.clientGroupsBlock {
			if util.ClientNameMatchesGroupName(blockGroup, cName) {
				groups = append(groups, groupsByName...)
			}
		}
	}

	// try IP
	groupsByIP, found := r.clientGroupsBlock[request.ClientIP.String()]

	if found {
		groups = append(groups, groupsByIP...)
	}

	for clientIdentifier, groupsByCidr := range r.clientGroupsBlock {
		// try CIDR
		if util.CidrContainsIP(clientIdentifier, request.ClientIP) {
			groups = append(groups, groupsByCidr...)
		} else if isFQDN(clientIdentifier) && r.fqdnIPCache != nil {
			ips, _ := r.fqdnIPCache.Get(clientIdentifier)
			if ips != nil {
				for _, ip := range *ips {
					if ip.Equal(request.ClientIP) {
						groups = append(groups, groupsByCidr...)
					}
				}
			}
		}
	}

	if len(groups) == 0 {
		// return default
		groups = r.clientGroupsBlock["default"]
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
	domain string,
) (group []string) {
	if len(groupsToCheck) > 0 {
		return m.Match(domain, groupsToCheck)
	}

	return []string{}
}

type blockHandler interface {
	handleBlock(question dns.Question, response *dns.Msg)
}

type zeroIPBlockHandler struct {
	BlockTimeSec uint32
}

type nxDomainBlockHandler struct{}

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

func (r *BlockingResolver) queryForFQIdentifierIPs(identifier string) (*[]net.IP, time.Duration) {
	prefixedLog := log.WithPrefix(r.log(), "client_id_cache")

	var result []net.IP

	var ttl time.Duration

	for _, qType := range []uint16{dns.TypeA, dns.TypeAAAA} {
		resp, err := r.next.Resolve(&model.Request{
			Req: util.NewMsgWithQuestion(identifier, dns.Type(qType)),
			Log: prefixedLog,
		})

		if err == nil && resp.Res.Rcode == dns.RcodeSuccess {
			for _, rr := range resp.Res.Answer {
				ttl = time.Duration(atomic.LoadUint32(&rr.Header().Ttl)) * time.Second

				switch v := rr.(type) {
				case *dns.A:
					result = append(result, v.A)
				case *dns.AAAA:
					result = append(result, v.AAAA)
				}
			}

			prefixedLog.Debugf("resolved IPs '%v' for fq identifier '%s'", result, identifier)
		}
	}

	return &result, ttl
}

func (r *BlockingResolver) initFQDNIPCache() {
	r.status.lock.Lock()
	defer r.status.lock.Unlock()

	identifiers := make([]string, 0)

	for identifier := range r.clientGroupsBlock {
		identifiers = append(identifiers, identifier)
	}

	r.fqdnIPCache = expirationcache.NewCache(expirationcache.WithCleanUpInterval[[]net.IP](defaultBlockingCleanUpInterval),
		expirationcache.WithOnExpiredFn(func(key string) (val *[]net.IP, ttl time.Duration) {
			return r.queryForFQIdentifierIPs(key)
		}))

	for _, identifier := range identifiers {
		if isFQDN(identifier) {
			iPs, ttl := r.queryForFQIdentifierIPs(identifier)
			r.fqdnIPCache.Put(identifier, iPs, ttl)
		}
	}
}

func isFQDN(in string) bool {
	s := strings.Trim(in, ".")

	return strings.Contains(s, ".")
}
