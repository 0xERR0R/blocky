package configapi_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"

	"github.com/0xERR0R/blocky/api/configapi"
	"github.com/0xERR0R/blocky/configstore"
	"github.com/go-chi/chi/v5"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// Integration tests exercise the full HTTP round-trip through chi router → handler → SQLite.
var _ = Describe("Config API HTTP integration", func() {
	var (
		srv    *httptest.Server
		store  *configstore.ConfigStore
		reconf *mockReconfigurer
	)

	BeforeEach(func() {
		var err error
		store, err = configstore.Open(filepath.Join(GinkgoT().TempDir(), "integration.db"))
		Expect(err).Should(Succeed())
		DeferCleanup(store.Close)

		reconf = &mockReconfigurer{}
		router := chi.NewRouter()
		configapi.RegisterEndpoints(router, configapi.NewConfigHandler(store, reconf))
		srv = httptest.NewServer(router)
		DeferCleanup(srv.Close)
	})

	// --- Client Groups round-trip ---

	It("creates, reads, updates, and deletes a client group via HTTP", func() {
		// PUT create
		resp := httpDo("PUT", srv.URL+"/api/config/client-groups/kids",
			`{"clients":["192.168.1.0/24"],"groups":["ads"]}`)
		Expect(resp.StatusCode).Should(Equal(200))

		var cg configapi.ClientGroup
		decodeBody(resp, &cg)
		Expect(cg.Name).Should(Equal("kids"))
		Expect(cg.Clients).Should(ConsistOf("192.168.1.0/24"))

		// GET
		resp = httpDo("GET", srv.URL+"/api/config/client-groups/kids", "")
		Expect(resp.StatusCode).Should(Equal(200))
		decodeBody(resp, &cg)
		Expect(cg.Name).Should(Equal("kids"))

		// PUT update
		resp = httpDo("PUT", srv.URL+"/api/config/client-groups/kids",
			`{"clients":["10.0.0.0/8"],"groups":["ads","malware"]}`)
		Expect(resp.StatusCode).Should(Equal(200))
		decodeBody(resp, &cg)
		Expect(cg.Groups).Should(ConsistOf("ads", "malware"))

		// LIST
		resp = httpDo("GET", srv.URL+"/api/config/client-groups", "")
		Expect(resp.StatusCode).Should(Equal(200))
		var groups []configapi.ClientGroup
		decodeBody(resp, &groups)
		Expect(groups).Should(HaveLen(1))

		// DELETE
		resp = httpDo("DELETE", srv.URL+"/api/config/client-groups/kids", "")
		Expect(resp.StatusCode).Should(Equal(204))

		// GET after delete → 404
		resp = httpDo("GET", srv.URL+"/api/config/client-groups/kids", "")
		Expect(resp.StatusCode).Should(Equal(404))
	})

	// --- Blocklist Sources round-trip ---

	It("creates and lists blocklist sources with filters via HTTP", func() {
		// Create two sources in different groups
		resp := httpDo("POST", srv.URL+"/api/config/blocklist-sources",
			`{"group_name":"ads","list_type":"deny","source_type":"http","source":"https://a.com/list.txt","enabled":true}`)
		Expect(resp.StatusCode).Should(Equal(201))

		resp = httpDo("POST", srv.URL+"/api/config/blocklist-sources",
			`{"group_name":"malware","list_type":"deny","source_type":"http","source":"https://b.com/list.txt","enabled":true}`)
		Expect(resp.StatusCode).Should(Equal(201))

		// List all
		resp = httpDo("GET", srv.URL+"/api/config/blocklist-sources", "")
		Expect(resp.StatusCode).Should(Equal(200))
		var sources []configapi.BlocklistSource
		decodeBody(resp, &sources)
		Expect(sources).Should(HaveLen(2))

		// Filter by group
		resp = httpDo("GET", srv.URL+"/api/config/blocklist-sources?group_name=ads", "")
		Expect(resp.StatusCode).Should(Equal(200))
		decodeBody(resp, &sources)
		Expect(sources).Should(HaveLen(1))
		Expect(sources[0].GroupName).Should(Equal("ads"))
	})

	// --- Custom DNS round-trip ---

	It("creates and retrieves custom DNS entries via HTTP", func() {
		resp := httpDo("POST", srv.URL+"/api/config/custom-dns",
			`{"domain":"myhost.lan","record_type":"A","value":"192.168.1.100","ttl":3600,"enabled":true}`)
		Expect(resp.StatusCode).Should(Equal(201))

		var entry configapi.CustomDNSEntry
		decodeBody(resp, &entry)
		Expect(entry.Domain).Should(Equal("myhost.lan"))
		Expect(entry.Value).Should(Equal("192.168.1.100"))

		// GET by ID
		resp = httpDo("GET", fmt.Sprintf("%s/api/config/custom-dns/%d", srv.URL, entry.Id), "")
		Expect(resp.StatusCode).Should(Equal(200))
	})

	// --- Block Settings round-trip ---

	It("gets and updates block settings via HTTP", func() {
		resp := httpDo("GET", srv.URL+"/api/config/block-settings", "")
		Expect(resp.StatusCode).Should(Equal(200))

		var bs configapi.BlockSettings
		decodeBody(resp, &bs)
		Expect(bs.BlockType).Should(Equal("ZEROIP"))

		resp = httpDo("PUT", srv.URL+"/api/config/block-settings",
			`{"block_type":"NXDOMAIN","block_ttl":"30m"}`)
		Expect(resp.StatusCode).Should(Equal(200))
		decodeBody(resp, &bs)
		Expect(bs.BlockType).Should(Equal("NXDOMAIN"))
	})

	// --- Apply round-trip ---

	It("calls apply and succeeds via HTTP", func() {
		resp := httpDo("POST", srv.URL+"/api/config/apply", "")
		Expect(resp.StatusCode).Should(Equal(200))

		var ar configapi.ApplyResponse
		decodeBody(resp, &ar)
		Expect(ar.Status).Should(Equal(configapi.Ok))
	})

	It("returns 500 when apply fails via HTTP", func() {
		reconf.err = fmt.Errorf("build chain failed")

		resp := httpDo("POST", srv.URL+"/api/config/apply", "")
		Expect(resp.StatusCode).Should(Equal(500))

		var ar configapi.ApplyResponse
		decodeBody(resp, &ar)
		Expect(ar.Status).Should(Equal(configapi.Error))
		Expect(ar.Error).ShouldNot(BeNil())
	})

	// --- Validation round-trip ---

	It("rejects invalid A record via HTTP", func() {
		resp := httpDo("POST", srv.URL+"/api/config/custom-dns",
			`{"domain":"bad.lan","record_type":"A","value":"not-an-ip","ttl":3600,"enabled":true}`)
		Expect(resp.StatusCode).Should(Equal(400))
	})

	It("rejects invalid block settings via HTTP", func() {
		resp := httpDo("PUT", srv.URL+"/api/config/block-settings",
			`{"block_type":"INVALID","block_ttl":"1h"}`)
		Expect(resp.StatusCode).Should(Equal(400))
	})

	// --- Full workflow: CRUD → apply ---

	It("exercises full workflow: create resources then apply", func() {
		// Create a client group
		resp := httpDo("PUT", srv.URL+"/api/config/client-groups/office",
			`{"clients":["10.0.0.0/24"],"groups":["corporate"]}`)
		Expect(resp.StatusCode).Should(Equal(200))

		// Create a blocklist source
		resp = httpDo("POST", srv.URL+"/api/config/blocklist-sources",
			`{"group_name":"corporate","list_type":"deny","source_type":"http","source":"https://block.example.com/list","enabled":true}`)
		Expect(resp.StatusCode).Should(Equal(201))

		// Create a custom DNS entry
		resp = httpDo("POST", srv.URL+"/api/config/custom-dns",
			`{"domain":"intranet.corp","record_type":"A","value":"10.0.0.1","ttl":300,"enabled":true}`)
		Expect(resp.StatusCode).Should(Equal(201))

		// Update block settings
		resp = httpDo("PUT", srv.URL+"/api/config/block-settings",
			`{"block_type":"ZEROIP","block_ttl":"1h"}`)
		Expect(resp.StatusCode).Should(Equal(200))

		// Apply
		resp = httpDo("POST", srv.URL+"/api/config/apply", "")
		Expect(resp.StatusCode).Should(Equal(200))

		var ar configapi.ApplyResponse
		decodeBody(resp, &ar)
		Expect(ar.Status).Should(Equal(configapi.Ok))

		// Verify data persisted: list sources should have 1 entry
		resp = httpDo("GET", srv.URL+"/api/config/blocklist-sources", "")
		Expect(resp.StatusCode).Should(Equal(200))
		var sources []configapi.BlocklistSource
		decodeBody(resp, &sources)
		Expect(sources).Should(HaveLen(1))
		Expect(sources[0].GroupName).Should(Equal("corporate"))
	})
})

func httpDo(method, url, body string) *http.Response {
	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}

	req, err := http.NewRequestWithContext(context.Background(), method, url, bodyReader)
	Expect(err).Should(Succeed())

	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := http.DefaultClient.Do(req)
	Expect(err).Should(Succeed())

	return resp
}

func decodeBody(resp *http.Response, v any) {
	defer resp.Body.Close()

	Expect(json.NewDecoder(resp.Body).Decode(v)).Should(Succeed())
}
