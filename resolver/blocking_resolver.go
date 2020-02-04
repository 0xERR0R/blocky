package resolver

import (
	"blocky/config"
	"blocky/lists"
	"blocky/util"
	"fmt"
	"net"
	"reflect"
	"sort"
	"strings"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
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

	logrus.Fatalf("unknown blockType, please use one of: ZeroIP, NxDomain")

	return ZeroIP
}

// checks request's question (domain name) against black and white lists
type BlockingResolver struct {
	NextResolver
	blacklistMatcher    lists.Matcher
	whitelistMatcher    lists.Matcher
	clientGroupsBlock   map[string][]string
	blockType           BlockType
	whitelistOnlyGroups []string
}

func NewBlockingResolver(cfg config.BlockingConfig) ChainedResolver {
	bt := resolveBlockType(cfg)
	blacklistMatcher := lists.NewListCache(cfg.BlackLists, cfg.RefreshPeriod)
	whitelistMatcher := lists.NewListCache(cfg.WhiteLists, cfg.RefreshPeriod)
	whitelistOnlyGroups := determineWhitelistOnlyGroups(&cfg)

	return &BlockingResolver{
		blockType:           bt,
		clientGroupsBlock:   cfg.ClientGroupsBlock,
		blacklistMatcher:    blacklistMatcher,
		whitelistMatcher:    whitelistMatcher,
		whitelistOnlyGroups: whitelistOnlyGroups,
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
func (r *BlockingResolver) handleBlocked(question dns.Question, response *dns.Msg) (*dns.Msg, error) {
	switch r.blockType {
	case ZeroIP:
		rr, err := util.CreateAnswerFromQuestion(question, typeToZeroIP[question.Qtype], BlockTTL)
		if err != nil {
			return nil, err
		}

		response.Answer = append(response.Answer, rr)

	case NxDomain:
		response.Rcode = dns.RcodeNameError
	}

	return response, nil
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

func (r *BlockingResolver) Resolve(request *Request) (*Response, error) {
	logger := withPrefix(request.Log, "blacklist_resolver")
	groupsToCheck := r.groupsToCheckForClient(request)

	if len(groupsToCheck) > 0 {
		logger.WithField("groupsToCheck", strings.Join(groupsToCheck, "; ")).Debug("checking groups for request")

		for _, question := range request.Req.Question {
			domain := util.ExtractDomain(question)
			logger := logger.WithField("domain", domain)
			whitelistOnlyAlowed := reflect.DeepEqual(groupsToCheck, r.whitelistOnlyGroups)

			if whitelisted, group := r.matches(groupsToCheck, r.whitelistMatcher, domain); whitelisted {
				logger.WithField("group", group).Debugf("domain is whitelisted")
			} else {
				if whitelistOnlyAlowed {
					logger.WithField("client_groups", groupsToCheck).Debug("white list only for client group(s), blocking...")
					response := new(dns.Msg)
					response.SetReply(request.Req)
					resp, err := r.handleBlocked(question, response)

					return &Response{Res: resp, Reason: fmt.Sprintf("BLOCKED (WHITELIST ONLY)")}, err
				}
				if blocked, group := r.matches(groupsToCheck, r.blacklistMatcher, domain); blocked {
					logger.WithField("group", group).Debug("domain is blocked")

					response := new(dns.Msg)
					response.SetReply(request.Req)
					resp, err := r.handleBlocked(question, response)

					return &Response{Res: resp, Reason: fmt.Sprintf("BLOCKED (%s)", group)}, err
				}
			}
		}
	}

	logger.WithField("next_resolver", r.next).Trace("go to next resolver")

	return r.next.Resolve(request)
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

func (r BlockingResolver) String() string {
	return fmt.Sprintf("blacklist resolver")
}
