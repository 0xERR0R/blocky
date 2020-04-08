package cmd

import (
	"blocky/api"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
)

func testHTTPAPIServer(fn func(w http.ResponseWriter, r *http.Request)) *httptest.Server {
	ts := httptest.NewServer(http.HandlerFunc(fn))
	url, _ := url.Parse(ts.URL)
	apiHost = url.Hostname()
	port, _ := strconv.Atoi(url.Port())
	apiPort = uint16(port)

	return ts
}

func TestEnable(t *testing.T) {
	ts := testHTTPAPIServer(func(w http.ResponseWriter, r *http.Request) {})
	defer ts.Close()
	enableBlocking(nil, []string{})
}

func TestDisable(t *testing.T) {
	ts := testHTTPAPIServer(func(w http.ResponseWriter, r *http.Request) {})
	defer ts.Close()
	disableBlocking(blockingCmd, []string{})
}

func TestStatus(t *testing.T) {
	ts := testHTTPAPIServer(func(w http.ResponseWriter, r *http.Request) {
		response, _ := json.Marshal(api.BlockingStatus{Enabled: true})
		_, _ = w.Write(response)
	})
	defer ts.Close()
	statusBlocking(nil, []string{})
}
