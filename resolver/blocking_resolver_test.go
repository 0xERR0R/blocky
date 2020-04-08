package resolver

import (
	"blocky/api"
	"blocky/config"
	"blocky/helpertest"
	"blocky/util"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func Test_Resolve_ClientName_IpZero(t *testing.T) {
	file := helpertest.TempFile("blocked1.com")
	defer file.Close()

	sut := NewBlockingResolver(chi.NewRouter(), config.BlockingConfig{
		BlackLists: map[string][]string{"gr1": {file.Name()}},
		ClientGroupsBlock: map[string][]string{
			"client1": {"gr1"},
		},
	})
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
}

func Test_Resolve_ClientIp_A_IpZero(t *testing.T) {
	file := helpertest.TempFile("blocked1.com")
	defer file.Close()

	sut := NewBlockingResolver(chi.NewRouter(), config.BlockingConfig{
		BlackLists: map[string][]string{"gr1": {file.Name()}},
		ClientGroupsBlock: map[string][]string{
			"192.168.178.55": {"gr1"},
		},
	})

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
}

func Test_Resolve_ClientWith2Names_A_IpZero(t *testing.T) {
	file1 := helpertest.TempFile("blocked1.com")
	defer file1.Close()

	file2 := helpertest.TempFile("blocked2.com")
	defer file2.Close()

	sut := NewBlockingResolver(chi.NewRouter(), config.BlockingConfig{
		BlackLists: map[string][]string{
			"gr1": {file1.Name()},
			"gr2": {file2.Name()},
		},
		ClientGroupsBlock: map[string][]string{
			"client1": {"gr1"},
			"altName": {"gr2"},
		},
	})

	// request in gr1
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

	// request in gr2
	req = util.NewMsgWithQuestion("blocked2.com.", dns.TypeA)
	resp, err = sut.Resolve(&Request{
		Req:         req,
		ClientNames: []string{"client1", "altName"},
		ClientIP:    net.ParseIP("192.168.178.55"),
		Log:         logrus.NewEntry(logrus.New()),
	})
	assert.NoError(t, err)
	assert.Equal(t, dns.RcodeSuccess, resp.Res.Rcode)
	assert.Equal(t, "blocked2.com.	21600	IN	A	0.0.0.0", resp.Res.Answer[0].String())
}

func Test_Resolve_Default_A_IpZero(t *testing.T) {
	file := helpertest.TempFile("blocked1.com")
	defer file.Close()

	sut := NewBlockingResolver(chi.NewRouter(), config.BlockingConfig{
		BlackLists: map[string][]string{"gr1": {file.Name()}},
		ClientGroupsBlock: map[string][]string{
			"default": {"gr1"},
		},
	})

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
}

func Test_Disable_Blocking(t *testing.T) {
	file := helpertest.TempFile("blocked1.com")
	defer file.Close()

	sut := NewBlockingResolver(chi.NewRouter(), config.BlockingConfig{
		BlackLists: map[string][]string{"gr1": {file.Name()}},
		ClientGroupsBlock: map[string][]string{
			"default": {"gr1"},
		},
	}).(*BlockingResolver)

	m := &resolverMock{}
	m.On("Resolve", mock.Anything).Return(new(Response), nil)
	sut.Next(m)

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
	m.AssertNumberOfCalls(t, "Resolve", 0)

	r, _ := http.NewRequest("GET", "/api/blocking/disable", nil)

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(sut.apiBlockingDisable)

	handler.ServeHTTP(rr, r)

	assert.Equal(t, http.StatusOK, rr.Code)

	// now is blocking disabled, query the url again
	req = util.NewMsgWithQuestion("blocked1.com.", dns.TypeA)
	_, err = sut.Resolve(&Request{
		Req:         req,
		ClientNames: []string{"unknown"},
		ClientIP:    net.ParseIP("192.168.178.1"),
		Log:         logrus.NewEntry(logrus.New()),
	})
	assert.NoError(t, err)
	m.AssertExpectations(t)
	m.AssertNumberOfCalls(t, "Resolve", 1)
}

func Test_Disable_BlockingWithWrongParam(t *testing.T) {
	sut := NewBlockingResolver(chi.NewRouter(), config.BlockingConfig{}).(*BlockingResolver)

	r, _ := http.NewRequest("GET", "/api/blocking/disable?duration=xyz", nil)

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(sut.apiBlockingDisable)

	handler.ServeHTTP(rr, r)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func Test_Status_Blocking(t *testing.T) {
	sut := NewBlockingResolver(chi.NewRouter(), config.BlockingConfig{}).(*BlockingResolver)

	// enable blocking
	r, _ := http.NewRequest("GET", "/api/blocking/enable", nil)

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(sut.apiBlockingEnable)

	handler.ServeHTTP(rr, r)
	assert.Equal(t, http.StatusOK, rr.Code)

	// query status
	r, _ = http.NewRequest("GET", "/api/blocking/status", nil)

	rr = httptest.NewRecorder()
	handler = sut.apiBlockingStatus

	handler.ServeHTTP(rr, r)
	assert.Equal(t, http.StatusOK, rr.Code)

	var result api.BlockingStatus
	err := json.NewDecoder(rr.Body).Decode(&result)
	assert.NoError(t, err)

	assert.True(t, result.Enabled)

	// now disable blocking

	r, _ = http.NewRequest("GET", "/api/blocking/disable", nil)

	rr = httptest.NewRecorder()
	handler = sut.apiBlockingDisable

	handler.ServeHTTP(rr, r)
	assert.Equal(t, http.StatusOK, rr.Code)

	// now query status again

	r, _ = http.NewRequest("GET", "/api/blocking/status", nil)

	rr = httptest.NewRecorder()
	handler = sut.apiBlockingStatus

	handler.ServeHTTP(rr, r)
	assert.Equal(t, http.StatusOK, rr.Code)

	err = json.NewDecoder(rr.Body).Decode(&result)
	assert.NoError(t, err)

	assert.False(t, result.Enabled)
}

//nolint:funlen
func Test_Disable_BlockingWithDuration(t *testing.T) {
	file := helpertest.TempFile("blocked1.com")
	defer file.Close()

	sut := NewBlockingResolver(chi.NewRouter(), config.BlockingConfig{
		BlackLists: map[string][]string{"gr1": {file.Name()}},
		ClientGroupsBlock: map[string][]string{
			"default": {"gr1"},
		},
	}).(*BlockingResolver)

	m := &resolverMock{}
	m.On("Resolve", mock.Anything).Return(new(Response), nil)
	sut.Next(m)

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
	m.AssertNumberOfCalls(t, "Resolve", 0)

	// disable for 0.5 sec
	r, _ := http.NewRequest("GET", "/api/blocking/disable?duration=500ms", nil)

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(sut.apiBlockingDisable)

	handler.ServeHTTP(rr, r)

	assert.Equal(t, http.StatusOK, rr.Code)

	// now is blocking disabled, query the url again
	req = util.NewMsgWithQuestion("blocked1.com.", dns.TypeA)
	_, err = sut.Resolve(&Request{
		Req:         req,
		ClientNames: []string{"unknown"},
		ClientIP:    net.ParseIP("192.168.178.1"),
		Log:         logrus.NewEntry(logrus.New()),
	})
	assert.NoError(t, err)
	m.AssertExpectations(t)
	m.AssertNumberOfCalls(t, "Resolve", 1)

	// wait 1 sec
	time.Sleep(time.Second)

	req = util.NewMsgWithQuestion("blocked1.com.", dns.TypeA)
	resp, err = sut.Resolve(&Request{
		Req:         req,
		ClientNames: []string{"unknown"},
		ClientIP:    net.ParseIP("192.168.178.1"),
		Log:         logrus.NewEntry(logrus.New()),
	})
	assert.NoError(t, err)
	assert.Equal(t, dns.RcodeSuccess, resp.Res.Rcode)
	assert.Equal(t, "blocked1.com.	21600	IN	A	0.0.0.0", resp.Res.Answer[0].String())
}

func Test_Resolve_Default_Block_With_Whitelist(t *testing.T) {
	file := helpertest.TempFile("blocked1.com")
	defer file.Close()

	sut := NewBlockingResolver(chi.NewRouter(), config.BlockingConfig{
		BlackLists: map[string][]string{"gr1": {file.Name()}},
		WhiteLists: map[string][]string{"gr1": {file.Name()}},
		ClientGroupsBlock: map[string][]string{
			"default": {"gr1"},
		},
	})

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
	m.AssertExpectations(t)
}

func Test_Resolve_Whitelist_Only(t *testing.T) {
	file := helpertest.TempFile("whitelisted.com")
	defer file.Close()

	sut := NewBlockingResolver(chi.NewRouter(), config.BlockingConfig{
		WhiteLists: map[string][]string{"gr1": {file.Name()}},
		ClientGroupsBlock: map[string][]string{
			"default": {"gr1"},
		},
	})

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
	m.AssertExpectations(t)

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
	assert.Equal(t, 1, len(m.Calls))
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
	file := helpertest.TempFile("BLOCKED1.com")
	defer file.Close()

	sut := NewBlockingResolver(chi.NewRouter(), config.BlockingConfig{
		BlackLists: map[string][]string{"gr1": {file.Name()}},
		ClientGroupsBlock: map[string][]string{
			"default": {"gr1"},
		},
		BlockType: "NxDomain",
	})

	req := util.NewMsgWithQuestion("blocked1.com.", dns.TypeA)
	resp, err := sut.Resolve(&Request{
		Req:         req,
		ClientNames: []string{"unknown"},
		ClientIP:    net.ParseIP("192.168.178.1"),
		Log:         logrus.NewEntry(logrus.New()),
	})
	assert.NoError(t, err)
	assert.Equal(t, dns.RcodeNameError, resp.Res.Rcode)
}

func Test_Resolve_Default_BlockIP_A(t *testing.T) {
	file := helpertest.TempFile("123.145.123.145")
	defer file.Close()

	sut := NewBlockingResolver(chi.NewRouter(), config.BlockingConfig{
		BlackLists: map[string][]string{"gr1": {file.Name()}},
		ClientGroupsBlock: map[string][]string{
			"default": {"gr1"},
		},
	})

	m := &resolverMock{}
	mockResp, _ := util.NewMsgWithAnswer("example.com. 300 IN A 123.145.123.145")

	m.On("Resolve", mock.Anything).Return(&Response{Res: mockResp}, nil)
	sut.Next(m)

	req := util.NewMsgWithQuestion("example.com.", dns.TypeA)
	resp, err := sut.Resolve(&Request{
		Req:         req,
		ClientNames: []string{"unknown"},
		ClientIP:    net.ParseIP("192.168.178.1"),
		Log:         logrus.NewEntry(logrus.New()),
	})
	assert.NoError(t, err)
	assert.Equal(t, dns.RcodeSuccess, resp.Res.Rcode)
	assert.Equal(t, "example.com.	21600	IN	A	0.0.0.0", resp.Res.Answer[0].String())
}

func Test_Resolve_Default_BlockIP_AAAA(t *testing.T) {
	file := helpertest.TempFile("2001:db8:85a3:08d3::370:7344")
	defer file.Close()

	sut := NewBlockingResolver(chi.NewRouter(), config.BlockingConfig{
		BlackLists: map[string][]string{"gr1": {file.Name()}},
		ClientGroupsBlock: map[string][]string{
			"default": {"gr1"},
		},
	})

	m := &resolverMock{}
	mockResp, _ := util.NewMsgWithAnswer("example.com. 300 IN AAAA 2001:0db8:85a3:08d3::0370:7344")

	m.On("Resolve", mock.Anything).Return(&Response{Res: mockResp}, nil)
	sut.Next(m)

	req := util.NewMsgWithQuestion("example.com.", dns.TypeAAAA)
	resp, err := sut.Resolve(&Request{
		Req:         req,
		ClientNames: []string{"unknown"},
		ClientIP:    net.ParseIP("192.168.178.1"),
		Log:         logrus.NewEntry(logrus.New()),
	})
	assert.NoError(t, err)
	assert.Equal(t, dns.RcodeSuccess, resp.Res.Rcode)
	assert.Equal(t, "BLOCKED IP (gr1)", resp.Reason)
	assert.Equal(t, "example.com.	21600	IN	AAAA	::", resp.Res.Answer[0].String())
}

func Test_Resolve_Default_BlockIP_A_With_Whitelist(t *testing.T) {
	file := helpertest.TempFile("123.145.123.145")
	defer file.Close()

	sut := NewBlockingResolver(chi.NewRouter(), config.BlockingConfig{
		BlackLists: map[string][]string{"gr1": {file.Name()}},
		WhiteLists: map[string][]string{"gr1": {file.Name()}},
		ClientGroupsBlock: map[string][]string{
			"default": {"gr1"},
		},
	})

	m := &resolverMock{}
	mockResp, _ := util.NewMsgWithAnswer("example.com. 300 IN A 123.145.123.145")

	m.On("Resolve", mock.Anything).Return(&Response{Res: mockResp}, nil)
	sut.Next(m)

	req := util.NewMsgWithQuestion("blocked1.com.", dns.TypeA)
	_, err := sut.Resolve(&Request{
		Req:         req,
		ClientNames: []string{"unknown"},
		ClientIP:    net.ParseIP("123.145.123.145"),
		Log:         logrus.NewEntry(logrus.New()),
	})
	assert.NoError(t, err)
	m.AssertExpectations(t)
}

func Test_Resolve_Default_Block_CNAME(t *testing.T) {
	file := helpertest.TempFile("baddomain.com")
	defer file.Close()

	sut := NewBlockingResolver(chi.NewRouter(), config.BlockingConfig{
		BlackLists: map[string][]string{"gr1": {file.Name()}},
		ClientGroupsBlock: map[string][]string{
			"default": {"gr1"},
		},
	})

	m := &resolverMock{}

	rr1, err1 := dns.NewRR("example.com 300 IN CNAME domain.com")
	rr2, err2 := dns.NewRR("domain.com 300 IN CNAME baddomain.com")
	rr3, err3 := dns.NewRR("baddomain.com 300 IN A 123.145.123.145")

	assert.NoError(t, err1)
	assert.NoError(t, err2)
	assert.NoError(t, err3)

	mockResp := new(dns.Msg)
	mockResp.Answer = []dns.RR{rr1, rr2, rr3}

	m.On("Resolve", mock.Anything).Return(&Response{Res: mockResp}, nil)
	sut.Next(m)

	req := util.NewMsgWithQuestion("example.com.", dns.TypeA)
	resp, err := sut.Resolve(&Request{
		Req:         req,
		ClientNames: []string{"unknown"},
		ClientIP:    net.ParseIP("192.168.178.1"),
		Log:         logrus.NewEntry(logrus.New()),
	})
	assert.NoError(t, err)
	assert.Equal(t, dns.RcodeSuccess, resp.Res.Rcode)
	assert.Equal(t, "example.com.	21600	IN	A	0.0.0.0", resp.Res.Answer[0].String())
}

func Test_Resolve_NoBlock(t *testing.T) {
	file := helpertest.TempFile("blocked1.com")
	defer file.Close()

	sut := NewBlockingResolver(chi.NewRouter(), config.BlockingConfig{
		BlackLists: map[string][]string{"gr1": {file.Name()}},
		ClientGroupsBlock: map[string][]string{
			"client1": {"gr1"},
		},
	})

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
	m.AssertExpectations(t)
}

func Test_Configuration_BlockingResolver(t *testing.T) {
	file := helpertest.TempFile("blocked1.com")
	defer file.Close()

	sut := NewBlockingResolver(chi.NewRouter(), config.BlockingConfig{
		BlackLists: map[string][]string{"gr1": {file.Name()}},
		WhiteLists: map[string][]string{"gr1": {file.Name()}},
		ClientGroupsBlock: map[string][]string{
			"default": {"gr1"},
		},
	})

	c := sut.Configuration()
	assert.True(t, len(c) > 1)
}

func Test_Resolve_WrongBlockType(t *testing.T) {
	defer func() { logrus.StandardLogger().ExitFunc = nil }()

	var fatal bool

	logrus.StandardLogger().ExitFunc = func(int) { fatal = true }

	_ = NewBlockingResolver(chi.NewRouter(), config.BlockingConfig{
		BlockType: "wrong",
	})

	assert.True(t, fatal)
}

func Test_Resolve_NoLists(t *testing.T) {
	sut := NewBlockingResolver(chi.NewRouter(), config.BlockingConfig{})
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
	m.AssertExpectations(t)

	c := sut.Configuration()

	assert.Equal(t, []string{"deactivated"}, c)
}
