package resolver

import (
	"blocky/config"
	"blocky/util"
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

var clientBlock = map[string][]string{
	"default":        {"gr0"},
	"client1":        {"gr1", "gr2"},
	"altName":        {"gr4"},
	"192.168.178.55": {"gr3"},
}

type MatcherMock struct {
	mock.Mock
}

func (b *MatcherMock) Configuration() (result []string) {
	return
}

func (b *MatcherMock) Match(domain string, groupsToCheck []string) (found bool, group string) {
	args := b.Called(domain, groupsToCheck)
	return args.Bool(0), args.String(1)
}

func Test_Resolve_ClientName_IpZero(t *testing.T) {
	b := &MatcherMock{}
	b.On("Match", "blocked1.com", []string{"gr1", "gr2", "gr3"}).Return(true, "gr1")

	w := &MatcherMock{}
	w.On("Match", mock.Anything, mock.Anything).Return(false, "gr1")

	sut := BlockingResolver{
		clientGroupsBlock: clientBlock,
		blacklistMatcher:  b,
		whitelistMatcher:  w,
	}

	req := util.NewMsgWithQuestion("blocked1.com.", dns.TypeA)

	// A
	resp, err := sut.Resolve(&Request{
		Req:         req,
		ClientNames: []string{"client1"},
		ClientIP:    net.ParseIP("192.168.178.55"),
		Log:         logrus.NewEntry(logrus.New()),
	})
	assert.NoError(t, err)
	assert.Equal(t, dns.RcodeSuccess, resp.Res.Rcode)
	assert.Equal(t, "blocked1.com.	21600	IN	A	0.0.0.0", resp.Res.Answer[0].String())
	b.AssertExpectations(t)

	// AAAA
	req = util.NewMsgWithQuestion("blocked1.com.", dns.TypeAAAA)
	resp, err = sut.Resolve(&Request{
		Req:         req,
		ClientNames: []string{"client1"},
		ClientIP:    net.ParseIP("192.168.178.55"),
		Log:         logrus.NewEntry(logrus.New()),
	})
	assert.NoError(t, err)
	assert.Equal(t, dns.RcodeSuccess, resp.Res.Rcode)
	assert.Equal(t, "blocked1.com.	21600	IN	AAAA	::", resp.Res.Answer[0].String())
	b.AssertExpectations(t)
}

func Test_Resolve_ClientIp_A_IpZero(t *testing.T) {
	b := &MatcherMock{}
	b.On("Match", "blocked1.com", []string{"gr3"}).Return(true, "gr1")

	w := &MatcherMock{}
	w.On("Match", mock.Anything, mock.Anything).Return(false, "gr1")

	sut := BlockingResolver{
		clientGroupsBlock: clientBlock,
		blacklistMatcher:  b,
		whitelistMatcher:  w,
	}

	req := util.NewMsgWithQuestion("blocked1.com.", dns.TypeA)

	resp, err := sut.Resolve(&Request{
		Req:         req,
		ClientNames: []string{"unknown"},
		ClientIP:    net.ParseIP("192.168.178.55"),
		Log:         logrus.NewEntry(logrus.New()),
	})
	assert.NoError(t, err)
	assert.Equal(t, dns.RcodeSuccess, resp.Res.Rcode)
	assert.Equal(t, "blocked1.com.	21600	IN	A	0.0.0.0", resp.Res.Answer[0].String())
	b.AssertExpectations(t)
}

func Test_Resolve_ClientWith2Names_A_IpZero(t *testing.T) {
	b := &MatcherMock{}
	b.On("Match", "blocked1.com", []string{"gr1", "gr2", "gr3", "gr4"}).Return(true, "gr1")

	w := &MatcherMock{}
	w.On("Match", mock.Anything, mock.Anything).Return(false, "gr1")

	sut := BlockingResolver{
		clientGroupsBlock: clientBlock,
		blacklistMatcher:  b,
		whitelistMatcher:  w,
	}

	req := util.NewMsgWithQuestion("blocked1.com.", dns.TypeA)
	resp, err := sut.Resolve(&Request{
		Req:         req,
		ClientNames: []string{"client1", "altName"},
		ClientIP:    net.ParseIP("192.168.178.55"),
		Log:         logrus.NewEntry(logrus.New()),
	})
	assert.NoError(t, err)
	assert.Equal(t, dns.RcodeSuccess, resp.Res.Rcode)
	assert.Equal(t, "blocked1.com.	21600	IN	A	0.0.0.0", resp.Res.Answer[0].String())

	b.AssertExpectations(t)
}

func Test_Resolve_Default_A_IpZero(t *testing.T) {
	b := &MatcherMock{}
	b.On("Match", "blocked1.com", []string{"gr0"}).Return(true, "gr1")

	w := &MatcherMock{}
	w.On("Match", mock.Anything, mock.Anything).Return(false, "gr1")

	sut := BlockingResolver{
		clientGroupsBlock: clientBlock,
		blacklistMatcher:  b,
		whitelistMatcher:  w,
	}

	req := util.NewMsgWithQuestion("blocked1.com.", dns.TypeA)
	resp, err := sut.Resolve(&Request{
		Req:         req,
		ClientNames: []string{"unknown"},
		ClientIP:    net.ParseIP("192.168.178.1"),
		Log:         logrus.NewEntry(logrus.New()),
	})
	assert.NoError(t, err)
	assert.Equal(t, dns.RcodeSuccess, resp.Res.Rcode)
	assert.Equal(t, "blocked1.com.	21600	IN	A	0.0.0.0", resp.Res.Answer[0].String())
	b.AssertExpectations(t)
}

func Test_Resolve_Default_Block_With_Whitelist(t *testing.T) {
	b := &MatcherMock{}
	b.On("Match", "blocked1.com", []string{"gr0"}).Return(true, "gr")

	w := &MatcherMock{}
	w.On("Match", "blocked1.com", []string{"gr0"}).Return(true, "gr1")

	sut := BlockingResolver{
		clientGroupsBlock: clientBlock,
		blacklistMatcher:  b,
		whitelistMatcher:  w,
	}

	m := &resolverMock{}
	m.On("Resolve", mock.Anything).Return(new(Response), nil)
	sut.Next(m)

	req := util.NewMsgWithQuestion("blocked1.com.", dns.TypeA)
	_, err := sut.Resolve(&Request{
		Req:         req,
		ClientNames: []string{"unknown"},
		ClientIP:    net.ParseIP("192.168.178.1"),
		Log:         logrus.NewEntry(logrus.New()),
	})
	assert.NoError(t, err)
	w.AssertExpectations(t)
	assert.Equal(t, 0, len(b.Calls))
}

func Test_Resolve_Whitelist_Only(t *testing.T) {
	b := &MatcherMock{}

	w := &MatcherMock{}
	w.On("Match", "whitelisted.com", []string{"gr0"}).Return(true, "gr0")
	w.On("Match", mock.Anything, []string{"gr0"}).Return(false, "gr0")

	sut := BlockingResolver{
		clientGroupsBlock:   clientBlock,
		blacklistMatcher:    b,
		whitelistMatcher:    w,
		whitelistOnlyGroups: []string{"gr0"},
	}

	m := &resolverMock{}
	m.On("Resolve", mock.Anything).Return(new(Response), nil)
	sut.Next(m)

	req := util.NewMsgWithQuestion("whitelisted.com.", dns.TypeA)
	_, err := sut.Resolve(&Request{
		Req:         req,
		ClientNames: []string{"unknown"},
		ClientIP:    net.ParseIP("192.168.178.1"),
		Log:         logrus.NewEntry(logrus.New()),
	})
	assert.NoError(t, err)
	w.AssertExpectations(t)
	assert.Equal(t, 0, len(b.Calls))

	req = new(dns.Msg)
	req.SetQuestion("google.com.", dns.TypeA)

	resp, err := sut.Resolve(&Request{
		Req:         req,
		ClientNames: []string{"unknown"},
		ClientIP:    net.ParseIP("192.168.178.1"),
		Log:         logrus.NewEntry(logrus.New()),
	})

	assert.NoError(t, err)
	assert.Equal(t, dns.RcodeSuccess, resp.Res.Rcode)
	assert.Equal(t, "google.com.	21600	IN	A	0.0.0.0", resp.Res.Answer[0].String())
	w.AssertExpectations(t)
	b.AssertExpectations(t)
}

func Test_determineWhitelistOnlyGroups(t *testing.T) {
	assert.Equal(t, []string{"w1"}, determineWhitelistOnlyGroups(&config.BlockingConfig{
		BlackLists: map[string][]string{},
		WhiteLists: map[string][]string{"w1": {"l1"}},
	}))

	assert.Equal(t, []string{"b1", "default"}, determineWhitelistOnlyGroups(&config.BlockingConfig{
		BlackLists: map[string][]string{
			"w1": {"y"},
		},
		WhiteLists: map[string][]string{
			"w1":      {"l1"},
			"default": {"s1"},
			"b1":      {"x"}},
	}))
}

func Test_Resolve_Default_A_NxRecord(t *testing.T) {
	b := &MatcherMock{}
	b.On("Match", "blocked1.com", []string{"gr0"}).Return(true, "gr1")

	w := &MatcherMock{}
	w.On("Match", mock.Anything, mock.Anything).Return(false, "gr1")

	sut := BlockingResolver{
		clientGroupsBlock: clientBlock,
		blacklistMatcher:  b,
		blockType:         NxDomain,
		whitelistMatcher:  w,
	}

	req := util.NewMsgWithQuestion("blocked1.com.", dns.TypeA)
	resp, err := sut.Resolve(&Request{
		Req:         req,
		ClientNames: []string{"unknown"},
		ClientIP:    net.ParseIP("192.168.178.1"),
		Log:         logrus.NewEntry(logrus.New()),
	})
	assert.NoError(t, err)
	assert.Equal(t, dns.RcodeNameError, resp.Res.Rcode)
	b.AssertExpectations(t)
}

func Test_Resolve_NoBlock(t *testing.T) {
	b := &MatcherMock{}
	b.On("Match", "example.com", []string{"gr0"}).Return(false, "")

	w := &MatcherMock{}
	w.On("Match", mock.Anything, mock.Anything).Return(false, "gr1")

	sut := BlockingResolver{
		clientGroupsBlock: clientBlock,
		blacklistMatcher:  b,
		blockType:         NxDomain,
		whitelistMatcher:  w,
	}
	m := &resolverMock{}
	m.On("Resolve", mock.Anything).Return(new(Response), nil)
	sut.Next(m)

	req := util.NewMsgWithQuestion("example.com.", dns.TypeA)
	_, err := sut.Resolve(&Request{
		Req:         req,
		ClientNames: []string{"unknown"},
		ClientIP:    net.ParseIP("192.168.178.1"),
		Log:         logrus.NewEntry(logrus.New()),
	})
	assert.NoError(t, err)
	b.AssertExpectations(t)
}
