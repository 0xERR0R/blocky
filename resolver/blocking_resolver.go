package resolver

import (
	"blocky/api"
	"blocky/config"
	"blocky/lists"
	"blocky/metrics"
	"blocky/util"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/go-chi/chi"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
)

const (
	BlockTTL = 6 * 60 * 60
)

type BlockType uint8

const (
	ZeroIP BlockType = iota
	NxDomain
)

func (b BlockType) String() string {
	return [...]string{"ZeroIP", "NxDomain"}[b]
}

// nolint:gochecknoglobals
var typeToZeroIP = map[uint16]net.IP{
	dns.TypeA:    net.IPv4zero,
	dns.TypeAAAA: net.IPv6zero,
}

func resolveBlockType(cfg config.BlockingConfig) BlockType {
	cfgBlockType := strings.TrimSpace(strings.ToUpper(cfg.BlockType))
	if cfgBlockType == "" || cfgBlockType == "ZEROIP" {
		return ZeroIP
	}

	if cfgBlockType == "NXDOMAIN" {
		return NxDomain
	}

	log.Fatalf("unknown blockType, please use one of: ZeroIP, NxDomain")

	return ZeroIP
}

type status struct {
	enabled      bool
	enabledGauge prometheus.Gauge
	enableTimer  *time.Timer
	disableEnd   time.Time
}

func (s *status) enableBlocking() {
	s.enableTimer.Stop()
	s.enabled = true

	if metrics.IsEnabled() {
		s.enabledGauge.Set(1)
	}
}

func (s *status) disableBlocking(duration time.Duration) {
	s.enableTimer.Stop()
	s.enabled = false

	if metrics.IsEnabled() {
		s.enabledGauge.Set(0)
	}

	s.disableEnd = time.Now().Add(duration)

	if duration == 0 {
		log.Info("disable blocking")
	} else {
		log.Infof("disable blocking for %s", duration)
		s.enableTimer = time.AfterFunc(duration, func() {
			s.enableBlocking()
			log.Info("blocking enabled again")
		})
	}
}

// checks request's question (domain name) against black and white lists
type BlockingResolver struct {
	NextResolver
	blacklistMatcher    lists.Matcher
	whitelistMatcher    lists.Matcher
	clientGroupsBlock   map[string][]string
	blockType           BlockType
	whitelistOnlyGroups []string
	status              status
}

func NewBlockingResolver(router *chi.Mux, cfg config.BlockingConfig) ChainedResolver {
	bt := resolveBlockType(cfg)
	blacklistMatcher := lists.NewListCache(lists.BLACKLIST, cfg.BlackLists, cfg.RefreshPeriod)
	whitelistMatcher := lists.NewListCache(lists.WHITELIST, cfg.WhiteLists, cfg.RefreshPeriod)
	whitelistOnlyGroups := determineWhitelistOnlyGroups(&cfg)

	var enabledGauge prometheus.Gauge

	if metrics.IsEnabled() {
		enabledGauge = prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "blocky_blocking_enabled",
			Help: "Blockings status",
		})
		enabledGauge.Set(1)

		metrics.RegisterMetric(enabledGauge)
	}

	res := &BlockingResolver{
		blockType:           bt,
		clientGroupsBlock:   cfg.ClientGroupsBlock,
		blacklistMatcher:    blacklistMatcher,
		whitelistMatcher:    whitelistMatcher,
		whitelistOnlyGroups: whitelistOnlyGroups,
		status: status{
			enabledGauge: enabledGauge,
			enabled:      true,
			enableTimer:  time.NewTimer(0),
		},
	}

	// register API endpoints
	router.Get(api.BlockingEnablePath, res.apiBlockingEnable)
	router.Get(api.BlockingDisablePath, res.apiBlockingDisable)
	router.Get(api.BlockingStatusPath, res.apiBlockingStatus)

	return res
}

// apiBlockingEnable is the http endpoint to enable the blocking status
// @Summary Enable blocking
// @Description enable the blocking status
// @Tags blocking
// @Success 200   "Blocking is enabled"
// @Router /blocking/enable [get]
func (r *BlockingResolver) apiBlockingEnable(_ http.ResponseWriter, _ *http.Request) {
	log.Info("enabling blocking...")
	r.status.enableBlocking()
}

// apiBlockingStatus is the http endpoint to get current blocking status
// @Summary Blocking status
// @Description get current blocking status
// @Tags blocking
// @Produce  json
// @Success 200 {object} api.BlockingStatus "Returns current blocking status"
// @Router /blocking/status [get]
func (r *BlockingResolver) apiBlockingStatus(rw http.ResponseWriter, _ *http.Request) {
	var autoEnableDuration time.Duration
	if !r.status.enabled && r.status.disableEnd.After(time.Now()) {
		autoEnableDuration = time.Until(r.status.disableEnd)
	}

	response, _ := json.Marshal(api.BlockingStatus{
		Enabled:         r.status.enabled,
		AutoEnableInSec: uint(autoEnableDuration.Seconds()),
	})
	_, err := rw.Write(response)

	if err != nil {
		log.Fatal("unable to write response ", err)
	}
}

// apiBlockingDisable is the http endpoint to disable the blocking status
// @Summary Disable blocking
// @Description disable the blocking status
// @Tags blocking
// @Param duration query string false "duration of blocking (Example: 300s, 5m, 1h, 5m30s)" Format(duration)
// @Success 200   "Blocking is disabled"
// @Failure 400   "Wrong duration format"
// @Router /blocking/disable [get]
func (r *BlockingResolver) apiBlockingDisable(rw http.ResponseWriter, req *http.Request) {
	var (
		duration time.Duration
		err      error
	)

	// parse duration from query parameter
	durationParam := req.URL.Query().Get("duration")
	if len(durationParam) > 0 {
		duration, err = time.ParseDuration(durationParam)
		if err != nil {
			log.Errorf("wrong duration format '%s'", durationParam)
			rw.WriteHeader(http.StatusBadRequest)

			return
		}
	}

	r.status.disableBlocking(duration)
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
func (r *BlockingResolver) handleBlocked(logger *log.Entry,
	request *Request, question dns.Question, reason string) (*Response, error) {
	response := new(dns.Msg)
	response.SetReply(request.Req)

	switch r.blockType {
	case ZeroIP:
		rr := util.CreateAnswerFromQuestion(question, typeToZeroIP[question.Qtype], BlockTTL)

		response.Answer = append(response.Answer, rr)

	case NxDomain:
		response.Rcode = dns.RcodeNameError
	}

	logger.Debugf("blocking request '%s'", reason)

	return &Response{Res: response, RType: BLOCKED, Reason: reason}, nil
}

func (r *BlockingResolver) Configuration() (result []string) {
	if len(r.clientGroupsBlock) > 0 {
		result = append(result, "clientGroupsBlock")
		for key, val := range r.clientGroupsBlock {
			result = append(result, fmt.Sprintf("  %s = \"%s\"", key, strings.Join(val, ";")))
		}

		result = append(result, fmt.Sprintf("blockType = \"%s\"", r.blockType))

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

func shouldHandle(question dns.Question) bool {
	return question.Qtype == dns.TypeA || question.Qtype == dns.TypeAAAA
}

func (r *BlockingResolver) handleBlacklist(groupsToCheck []string,
	request *Request, logger *log.Entry) (*Response, error) {
	logger.WithField("groupsToCheck", strings.Join(groupsToCheck, "; ")).Debug("checking groups for request")
	whitelistOnlyAllowed := reflect.DeepEqual(groupsToCheck, r.whitelistOnlyGroups)

	for _, question := range request.Req.Question {
		if !shouldHandle(question) {
			return r.next.Resolve(request)
		}

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
		groupsByName, found := r.clientGroupsBlock[cName]
		if found {
			groups = append(groups, groupsByName...)
		}
	}

	// try IP
	groupsByIP, found := r.clientGroupsBlock[request.ClientIP.String()]

	if found {
		groups = append(groups, groupsByIP...)
	}

	if len(groups) == 0 {
		if !found {
			// return default
			groups = r.clientGroupsBlock["default"]
		}
	}

	sort.Strings(groups)

	return
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
