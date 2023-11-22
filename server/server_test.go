package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/docs"
	. "github.com/0xERR0R/blocky/helpertest"
	. "github.com/0xERR0R/blocky/log"
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/resolver"
	"github.com/0xERR0R/blocky/util"
	"github.com/creasty/defaults"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/miekg/dns"
)

const (
	httpBasePort  = 4000
	dnsBasePort   = 5000
	dnsBasePort2  = 55000
	httpsBasePort = 6000
	tlsBasePort   = 8000
)

var (
	mockClientName                                               atomic.Value
	sut                                                          *Server
	err                                                          error
	baseURL                                                      string
	queryURL                                                     string
	googleMockUpstream, fritzboxMockUpstream, clientMockUpstream *resolver.MockUDPUpstreamServer
)

var _ = BeforeSuite(func() {
	baseURL = "http://localhost:" + GetStringPort(httpBasePort) + "/"
	queryURL = baseURL + "dns-query"
	var upstreamGoogle, upstreamFritzbox, upstreamClient config.Upstream
	ctx, cancelFn := context.WithCancel(context.Background())
	DeferCleanup(cancelFn)
	googleMockUpstream = resolver.NewMockUDPUpstreamServer().WithAnswerFn(func(request *dns.Msg) (response *dns.Msg) {
		if request.Question[0].Name == "error." {
			return nil
		}
		response, err := util.NewMsgWithAnswer(
			util.ExtractDomain(request.Question[0]), 123, A, "123.124.122.122",
		)

		Expect(err).Should(Succeed())

		return response
	})
	DeferCleanup(googleMockUpstream.Close)

	fritzboxMockUpstream = resolver.NewMockUDPUpstreamServer().WithAnswerFn(func(request *dns.Msg) (response *dns.Msg) {
		response, err := util.NewMsgWithAnswer(
			util.ExtractDomain(request.Question[0]), 3600, A, "192.168.178.2",
		)

		Expect(err).Should(Succeed())

		return response
	})
	DeferCleanup(fritzboxMockUpstream.Close)

	clientMockUpstream = resolver.NewMockUDPUpstreamServer().WithAnswerFn(func(request *dns.Msg) (response *dns.Msg) {
		var clientName string

		if name, ok := mockClientName.Load().(string); ok {
			clientName = name
		}

		response, err := util.NewMsgWithAnswer(
			util.ExtractDomain(request.Question[0]), 3600, dns.Type(dns.TypePTR), clientName,
		)

		Expect(err).Should(Succeed())

		return response
	})
	DeferCleanup(clientMockUpstream.Close)

	upstreamClient = clientMockUpstream.Start()
	upstreamFritzbox = fritzboxMockUpstream.Start()
	upstreamGoogle = googleMockUpstream.Start()

	tmpDir := NewTmpFolder("server")
	Expect(tmpDir.Error).Should(Succeed())
	DeferCleanup(tmpDir.Clean)

	certPem := writeCertPem(tmpDir)
	Expect(certPem.Error).Should(Succeed())

	keyPem := writeKeyPem(tmpDir)
	Expect(keyPem.Error).Should(Succeed())

	doubleclickFile := tmpDir.CreateStringFile("doubleclick.net.txt", "doubleclick.net", "doubleclick.net.cn")
	Expect(doubleclickFile.Error).Should(Succeed())

	bildFile := tmpDir.CreateStringFile("www.bild.de.txt", "www.bild.de")
	Expect(bildFile.Error).Should(Succeed())

	heiseFile := tmpDir.CreateStringFile("heise.de.txt", "heise.de")
	Expect(heiseFile.Error).Should(Succeed())

	youtubeFile := tmpDir.CreateStringFile("youtube.com.txt", "youtube.com")
	Expect(youtubeFile.Error).Should(Succeed())

	cfg := &config.Config{
		CustomDNS: config.CustomDNS{
			CustomTTL: config.Duration(3600 * time.Second),
			Mapping: config.CustomDNSMapping{
				HostIPs: map[string][]net.IP{
					"custom.lan": {net.ParseIP("192.168.178.55")},
					"lan.home":   {net.ParseIP("192.168.178.56")},
				},
			},
		},
		Conditional: config.ConditionalUpstream{
			Mapping: config.ConditionalUpstreamMapping{
				Upstreams: map[string][]config.Upstream{
					"net.cn":    {upstreamClient},
					"fritz.box": {upstreamFritzbox},
				},
			},
		},
		Blocking: config.Blocking{
			BlackLists: map[string][]config.BytesSource{
				"ads": config.NewBytesSources(
					doubleclickFile.Path,
					bildFile.Path,
					heiseFile.Path,
				),
				"youtube": config.NewBytesSources(youtubeFile.Path),
			},
			WhiteLists: map[string][]config.BytesSource{
				"ads":       config.NewBytesSources(heiseFile.Path),
				"whitelist": config.NewBytesSources(heiseFile.Path),
			},
			ClientGroupsBlock: map[string][]string{
				"default":         {"ads"},
				"clWhitelistOnly": {"whitelist"},
				"clAdsAndYoutube": {"ads", "youtube"},
				"clYoutubeOnly":   {"youtube"},
			},
			BlockType: "zeroIp",
			BlockTTL:  config.Duration(6 * time.Hour),
		},
		Upstreams: config.Upstreams{
			Timeout: config.Duration(250 * time.Millisecond),
			Groups:  map[string][]config.Upstream{"default": {upstreamGoogle}},
		},
		ClientLookup: config.ClientLookup{
			Upstream: upstreamClient,
		},

		Ports: config.PortsConfig{
			DNS:   config.ListenConfig{GetStringPort(dnsBasePort)},
			TLS:   config.ListenConfig{GetStringPort(tlsBasePort)},
			HTTP:  config.ListenConfig{GetStringPort(httpBasePort)},
			HTTPS: config.ListenConfig{GetStringPort(httpsBasePort)},
		},
		CertFile: certPem.Path,
		KeyFile:  keyPem.Path,
		Prometheus: config.MetricsConfig{
			Enable: true,
			Path:   "/metrics",
		},
	}

	// create server
	sut, err = NewServer(ctx, cfg)
	Expect(err).Should(Succeed())

	errChan := make(chan error, 10)

	// start server
	go sut.Start(ctx, errChan)
	DeferCleanup(sut.Stop)

	Consistently(errChan, "1s").ShouldNot(Receive())
})

var _ = Describe("Running DNS server", func() {
	var (
		ctx      context.Context
		cancelFn context.CancelFunc
	)
	BeforeEach(func() {
		ctx, cancelFn = context.WithCancel(context.Background())
		DeferCleanup(cancelFn)
	})
	Describe("performing DNS request with running server", func() {
		BeforeEach(func() {
			mockClientName.Store("")
			// reset client cache
			clientNamesResolver, err := resolver.GetFromChainWithType[*resolver.ClientNamesResolver](sut.queryResolver)
			Expect(err).Should(Succeed())

			clientNamesResolver.FlushCache()
		})

		Context("DNS query is resolvable via external DNS", func() {
			It("should return valid answer", func() {
				Expect(requestServer(util.NewMsgWithQuestion("google.de.", A))).
					Should(
						SatisfyAll(
							BeDNSRecord("google.de.", A, "123.124.122.122"),
							HaveTTL(BeNumerically("==", 123)),
						))
			})
		})
		Context("Custom DNS entry with exact match", func() {
			It("should return valid answer", func() {
				Expect(requestServer(util.NewMsgWithQuestion("custom.lan.", A))).
					Should(
						SatisfyAll(
							BeDNSRecord("custom.lan.", A, "192.168.178.55"),
							HaveTTL(BeNumerically("==", 3600)),
						))
			})
		})
		Context("Custom DNS entry with sub domain", func() {
			It("should return valid answer", func() {
				Expect(requestServer(util.NewMsgWithQuestion("host.lan.home.", A))).
					Should(
						SatisfyAll(
							BeDNSRecord("host.lan.home.", A, "192.168.178.56"),
							HaveTTL(BeNumerically("==", 3600)),
						))
			})
		})
		Context("Conditional upstream", func() {
			It("should resolve query via conditional upstream resolver", func() {
				Expect(requestServer(util.NewMsgWithQuestion("host.fritz.box.", A))).
					Should(
						SatisfyAll(
							BeDNSRecord("host.fritz.box.", A, "192.168.178.2"),
							HaveTTL(BeNumerically("==", 3600)),
						))
			})
		})
		Context("Conditional upstream blocking", func() {
			It("Query should be blocked, domain is in default group", func() {
				Expect(requestServer(util.NewMsgWithQuestion("doubleclick.net.cn.", A))).
					Should(
						SatisfyAll(
							BeDNSRecord("doubleclick.net.cn.", A, "0.0.0.0"),
							HaveTTL(BeNumerically("==", 21600)),
						))
			})
		})
		Context("Blocking default group", func() {
			It("Query should be blocked, domain is in default group", func() {
				Expect(requestServer(util.NewMsgWithQuestion("doubleclick.net.", A))).
					Should(
						SatisfyAll(
							BeDNSRecord("doubleclick.net.", A, "0.0.0.0"),
							HaveTTL(BeNumerically("==", 21600)),
						))
			})
		})
		Context("Blocking default group with sub domain", func() {
			It("Query with subdomain should be blocked, domain is in default group", func() {
				Expect(requestServer(util.NewMsgWithQuestion("www.bild.de.", A))).
					Should(
						SatisfyAll(
							BeDNSRecord("www.bild.de.", A, "0.0.0.0"),
							HaveTTL(BeNumerically("==", 21600)),
						))
			})
		})
		Context("no blocking default group with sub domain", func() {
			It("Query with should not be blocked, sub domain is not in blacklist", func() {
				Expect(requestServer(util.NewMsgWithQuestion("bild.de.", A))).
					Should(
						SatisfyAll(
							BeDNSRecord("bild.de.", A, "123.124.122.122"),
							HaveTTL(BeNumerically("<=", 123)),
						))
			})
		})
		Context("domain is on white and blacklist default group", func() {
			It("Query with should not be blocked, domain is on white and blacklist", func() {
				Expect(requestServer(util.NewMsgWithQuestion("heise.de.", A))).
					Should(
						SatisfyAll(
							BeDNSRecord("heise.de.", A, "123.124.122.122"),
							HaveTTL(BeNumerically("<=", 123)),
						))
			})
		})
		Context("domain is on client specific white list", func() {
			It("Query with should not be blocked, domain is on client's white list", func() {
				mockClientName.Store("clWhitelistOnly")
				Expect(requestServer(util.NewMsgWithQuestion("heise.de.", A))).
					Should(
						SatisfyAll(
							BeDNSRecord("heise.de.", A, "123.124.122.122"),
							HaveTTL(BeNumerically("<=", 123)),
						))
			})
		})
		Context("block client whitelist only", func() {
			It("Query with should be blocked, client has only whitelist, domain is not on client's white list", func() {
				mockClientName.Store("clWhitelistOnly")
				Expect(requestServer(util.NewMsgWithQuestion("google.de.", A))).
					Should(
						SatisfyAll(
							BeDNSRecord("google.de.", A, "0.0.0.0"),
							HaveTTL(BeNumerically("==", 21600)),
						))
			})
		})
		Context("block client with 2 groups", func() {
			It("Query with should be blocked, domain is on black list", func() {
				mockClientName.Store("clAdsAndYoutube")

				Expect(requestServer(util.NewMsgWithQuestion("www.bild.de.", A))).
					Should(
						SatisfyAll(
							BeDNSRecord("www.bild.de.", A, "0.0.0.0"),
							HaveTTL(BeNumerically("==", 21600)),
						))

				Expect(requestServer(util.NewMsgWithQuestion("youtube.com.", A))).
					Should(
						SatisfyAll(
							BeDNSRecord("youtube.com.", A, "0.0.0.0"),
							HaveTTL(BeNumerically("==", 21600)),
						))
			})
		})
		Context("client with 1 group: no block if domain in other group", func() {
			It("Query with should not be blocked, domain is on black list in another group", func() {
				mockClientName.Store("clYoutubeOnly")

				Expect(requestServer(util.NewMsgWithQuestion("www.bild.de.", A))).
					Should(
						SatisfyAll(
							BeDNSRecord("www.bild.de.", A, "123.124.122.122"),
							HaveTTL(BeNumerically("<=", 123)),
						))
			})
		})
		Context("block client with 1 group", func() {
			It("Query with should not  blocked, domain is on black list in client's group", func() {
				mockClientName.Store("clYoutubeOnly")

				Expect(requestServer(util.NewMsgWithQuestion("youtube.com.", A))).
					Should(
						SatisfyAll(
							BeDNSRecord("youtube.com.", A, "0.0.0.0"),
							HaveTTL(BeNumerically("==", 21600)),
						))
			})
		})
		Context("health check", func() {
			It("Should always return dummy response", func() {
				resp := requestServer(util.NewMsgWithQuestion("healthcheck.blocky.", A))

				Expect(resp.Answer).Should(BeEmpty())
			})
		})
	})

	Describe("Prometheus endpoint", func() {
		When("Prometheus URL is called", func() {
			It("should return prometheus data", func() {
				resp, err := http.Get(baseURL + "metrics")
				Expect(err).Should(Succeed())
				Expect(resp).Should(HaveHTTPStatus(http.StatusOK))
			})
		})
	})
	Describe("Root endpoint", func() {
		When("Root URL is called", func() {
			It("should return root page", func() {
				resp, err := http.Get(baseURL)
				Expect(err).Should(Succeed())
				Expect(resp).Should(
					SatisfyAll(
						HaveHTTPStatus(http.StatusOK),
						HaveHTTPHeaderWithValue("Content-type", "text/html; charset=UTF-8"),
					))
			})
		})
	})
	Describe("Docs endpoints", func() {
		When("OpenApi URL is called", func() {
			It("should return openAPI definition file", func() {
				resp, err := http.Get(baseURL + "docs/openapi.yaml")
				Expect(err).Should(Succeed())
				Expect(resp).Should(
					SatisfyAll(
						HaveHTTPStatus(http.StatusOK),
						HaveHTTPHeaderWithValue("Content-type", "text/yaml"),
						HaveHTTPBody(docs.OpenAPI),
					))
			})
		})
	})

	Describe("DOH endpoint", func() {
		Context("DOH over GET (RFC 8484)", func() {
			When("DOH get request with 'example.com' is performed", func() {
				It("should get a valid response", func() {
					resp, err := http.Get(queryURL + "?dns=AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB")
					Expect(err).Should(Succeed())
					DeferCleanup(resp.Body.Close)

					Expect(resp).Should(HaveHTTPStatus(http.StatusOK))
					Expect(resp).Should(HaveHTTPHeaderWithValue("Content-type", "application/dns-message"))

					rawMsg, err := io.ReadAll(resp.Body)
					Expect(err).Should(Succeed())

					msg := new(dns.Msg)
					err = msg.Unpack(rawMsg)
					Expect(err).Should(Succeed())

					Expect(msg.Answer).Should(BeDNSRecord("www.example.com.", A, "123.124.122.122"))
				})
			})
			When("Request does not contain a valid DNS message", func() {
				It("should return 'Bad Request'", func() {
					resp, err := http.Get(queryURL + "?dns=xxxx")
					Expect(err).Should(Succeed())
					DeferCleanup(resp.Body.Close)

					Expect(resp).Should(HaveHTTPStatus(http.StatusBadRequest))
				})
			})
			When("Request's parameter does not contain a valid base64'", func() {
				It("should return 'Bad Request'", func() {
					resp, err := http.Get(queryURL + "?dns=äöä")
					Expect(err).Should(Succeed())
					DeferCleanup(resp.Body.Close)

					Expect(resp).Should(HaveHTTPStatus(http.StatusBadRequest))
				})
			})
			When("Request does not contain a dns parameter", func() {
				It("should return 'Bad Request'", func() {
					resp, err := http.Get(queryURL + "?test")
					Expect(err).Should(Succeed())
					DeferCleanup(resp.Body.Close)

					Expect(resp).Should(HaveHTTPStatus(http.StatusBadRequest))
				})
			})
			When("Request's dns parameter is too long'", func() {
				It("should return 'URI Too Long'", func() {
					longBase64msg := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("t", 513)))

					resp, err := http.Get(queryURL + "?dns=" + longBase64msg)
					Expect(err).Should(Succeed())
					DeferCleanup(resp.Body.Close)

					Expect(resp).Should(HaveHTTPStatus(http.StatusRequestURITooLong))
				})
			})
		})
		Context("DOH over POST (RFC 8484)", func() {
			var (
				resp *http.Response
				msg  *dns.Msg
			)
			When("DOH post request with 'example.com' is performed", func() {
				It("should get a valid response", func() {
					msg = util.NewMsgWithQuestion("www.example.com.", A)
					rawDNSMessage, err := msg.Pack()
					Expect(err).Should(Succeed())

					resp, err = http.Post(queryURL,
						"application/dns-message", bytes.NewReader(rawDNSMessage))
					Expect(err).Should(Succeed())
					DeferCleanup(resp.Body.Close)

					Expect(resp).Should(
						SatisfyAll(
							HaveHTTPStatus(http.StatusOK),
							HaveHTTPHeaderWithValue("Content-type", "application/dns-message"),
						))

					rawMsg, err := io.ReadAll(resp.Body)
					Expect(err).Should(Succeed())

					msg = new(dns.Msg)
					err = msg.Unpack(rawMsg)
					Expect(err).Should(Succeed())

					Expect(msg.Answer).Should(BeDNSRecord("www.example.com.", A, "123.124.122.122"))
				})
				It("should get a valid response, clientId is passed", func() {
					msg = util.NewMsgWithQuestion("www.example.com.", A)
					rawDNSMessage, err := msg.Pack()
					Expect(err).Should(Succeed())

					resp, err = http.Post(queryURL+"/client123",
						"application/dns-message", bytes.NewReader(rawDNSMessage))
					Expect(err).Should(Succeed())
					DeferCleanup(resp.Body.Close)

					Expect(resp).Should(
						SatisfyAll(
							HaveHTTPStatus(http.StatusOK),
							HaveHTTPHeaderWithValue("Content-type", "application/dns-message"),
						))
					rawMsg, err := io.ReadAll(resp.Body)
					Expect(err).Should(Succeed())

					msg = new(dns.Msg)
					err = msg.Unpack(rawMsg)
					Expect(err).Should(Succeed())

					Expect(msg.Answer).Should(BeDNSRecord("www.example.com.", A, "123.124.122.122"))
				})
			})
			When("POST payload exceeds 512 bytes", func() {
				It("should return 'Payload Too Large'", func() {
					largeMessage := []byte(strings.Repeat("t", 513))

					resp, err = http.Post(queryURL, "application/dns-message", bytes.NewReader(largeMessage))
					Expect(err).Should(Succeed())
					DeferCleanup(resp.Body.Close)

					Expect(resp).Should(HaveHTTPStatus(http.StatusRequestEntityTooLarge))
				})
			})
			When("Request has wrong type", func() {
				It("should return 'Unsupported Media Type'", func() {
					resp, err = http.Post(queryURL, "application/text", bytes.NewReader([]byte("a")))
					Expect(err).Should(Succeed())
					DeferCleanup(resp.Body.Close)

					Expect(resp).Should(HaveHTTPStatus(http.StatusUnsupportedMediaType))
				})
			})
			When("Internal error occurs", func() {
				It("should return 'Internal server error'", func() {
					msg = util.NewMsgWithQuestion("error.", A)
					rawDNSMessage, err := msg.Pack()
					Expect(err).Should(Succeed())

					resp, err = http.Post(queryURL,
						"application/dns-message", bytes.NewReader(rawDNSMessage))
					Expect(err).Should(Succeed())
					DeferCleanup(resp.Body.Close)

					Expect(resp).Should(HaveHTTPStatus(http.StatusInternalServerError))
				})
			})
		})
	})

	Describe("Server create", func() {
		var (
			cfg  config.Config
			cErr error
		)
		BeforeEach(func() {
			cErr = defaults.Set(&cfg)

			Expect(cErr).Should(Succeed())

			cfg.Upstreams.Groups = map[string][]config.Upstream{
				"default": {config.Upstream{Net: config.NetProtocolTcpUdp, Host: "1.1.1.1", Port: 53}},
			}

			cfg.Redis.Address = "test-fail"
		})
		When("Server is created", func() {
			It("is created without redis connection", func() {
				_, err = NewServer(ctx, &cfg)

				Expect(err).Should(Succeed())
			})
			It("can't be created if redis server is unavailable", func() {
				cfg.Redis.Required = true

				_, err = NewServer(ctx, &cfg)

				Expect(err).ShouldNot(Succeed())
			})
		})
	})

	Describe("Server start", Label("XX"), func() {
		When("Server start is called", func() {
			var (
				server  *Server
				errChan chan error
			)
			BeforeEach(func() {
				// create server
				server, err = NewServer(ctx, &config.Config{
					Upstreams: config.Upstreams{
						Groups: map[string][]config.Upstream{
							"default": {config.Upstream{Net: config.NetProtocolTcpUdp, Host: "4.4.4.4", Port: 53}},
						},
					},
					CustomDNS: config.CustomDNS{
						Mapping: config.CustomDNSMapping{
							HostIPs: map[string][]net.IP{
								"custom.lan": {net.ParseIP("192.168.178.55")},
								"lan.home":   {net.ParseIP("192.168.178.56")},
							},
						},
					},
					Blocking: config.Blocking{BlockType: "zeroIp"},
					Ports: config.PortsConfig{
						DNS: config.ListenConfig{"127.0.0.1:" + GetStringPort(dnsBasePort2)},
					},
				})

				Expect(err).Should(Succeed())

				errChan = make(chan error, 10)
				// start server
				go server.Start(ctx, errChan)

				DeferCleanup(server.Stop)
			})
			It("start was called 2 times, start should fail", func() {
				Consistently(errChan, "1s").ShouldNot(Receive())

				// start again -> should fail
				server.Start(ctx, errChan)

				Eventually(errChan).Should(Receive())
			})
		})
	})
	Describe("Server stop", func() {
		When("Stop is called", func() {
			var (
				server  *Server
				errChan chan error
			)
			BeforeEach(func() {
				// create server
				server, err = NewServer(ctx, &config.Config{
					Upstreams: config.Upstreams{
						Groups: map[string][]config.Upstream{
							"default": {config.Upstream{Net: config.NetProtocolTcpUdp, Host: "4.4.4.4", Port: 53}},
						},
					},
					CustomDNS: config.CustomDNS{
						Mapping: config.CustomDNSMapping{
							HostIPs: map[string][]net.IP{
								"custom.lan": {net.ParseIP("192.168.178.55")},
								"lan.home":   {net.ParseIP("192.168.178.56")},
							},
						},
					},
					Blocking: config.Blocking{BlockType: "zeroIp"},
					Ports: config.PortsConfig{
						DNS: config.ListenConfig{"127.0.0.1:" + GetStringPort(dnsBasePort2)},
					},
				})

				Expect(err).Should(Succeed())

				errChan = make(chan error, 10)
			})
			It("stop was called 2 times, start should fail", func() {
				// start server
				go server.Start(ctx, errChan)

				time.Sleep(100 * time.Millisecond)

				err = server.Stop()

				// stop server, should be ok
				Expect(err).Should(Succeed())

				// stop again, should raise error
				err = server.Stop()

				Expect(err).Should(HaveOccurred())
			})
		})
	})

	Describe("resolve client IP", func() {
		Context("UDP address", func() {
			It("should correct resolve client IP", func() {
				ip, protocol := resolveClientIPAndProtocol(&net.UDPAddr{IP: net.ParseIP("192.168.178.88")})
				Expect(ip).Should(Equal(net.ParseIP("192.168.178.88")))
				Expect(protocol).Should(Equal(model.RequestProtocolUDP))
			})
		})
		Context("TCP address", func() {
			It("should correct resolve client IP", func() {
				ip, protocol := resolveClientIPAndProtocol(&net.TCPAddr{IP: net.ParseIP("192.168.178.88")})
				Expect(ip).Should(Equal(net.ParseIP("192.168.178.88")))
				Expect(protocol).Should(Equal(model.RequestProtocolTCP))
			})
		})
	})

	Describe("self-signed certificate creation", func() {
		var (
			cfg  config.Config
			cErr error
		)
		BeforeEach(func() {
			cErr = defaults.Set(&cfg)

			Expect(cErr).Should(Succeed())

			cfg.Upstreams.Groups = map[string][]config.Upstream{
				"default": {config.Upstream{Net: config.NetProtocolTcpUdp, Host: "1.1.1.1", Port: 53}},
			}
		})

		It("should create self-signed certificate if key/cert files are not provided", func() {
			cfg.KeyFile = ""
			cfg.CertFile = ""
			cfg.Ports = config.PortsConfig{
				HTTPS: []string{fmt.Sprintf(":%d", GetIntPort(httpsBasePort)+100)},
			}
			sut, err := NewServer(ctx, &cfg)
			Expect(err).Should(Succeed())
			Expect(sut.cert.Certificate).ShouldNot(BeNil())
		})
	})
})

func requestServer(request *dns.Msg) *dns.Msg {
	conn, err := net.Dial("udp", ":"+GetStringPort(dnsBasePort))
	if err != nil {
		Log().Fatal("could not connect to server: ", err)
	}
	defer conn.Close()

	msg, err := request.Pack()
	if err != nil {
		Log().Fatal("can't pack request: ", err)
	}

	_, err = conn.Write(msg)
	if err != nil {
		Log().Fatal("can't send request to server: ", err)
	}

	out := make([]byte, 1024)

	if _, err := conn.Read(out); err == nil {
		response := new(dns.Msg)

		err = response.Unpack(out)

		if err != nil {
			Log().Fatal("can't unpack response: ", err)
		}

		return response
	}

	Log().Fatal("could not read from connection", err)

	return nil
}

func writeCertPem(tmpDir *TmpFolder) *TmpFile {
	return tmpDir.CreateStringFile("cert.pem",
		"-----BEGIN CERTIFICATE-----",
		"MIICMzCCAZygAwIBAgIRAJCCrDTGEtZfRpxDY1KAoswwDQYJKoZIhvcNAQELBQAw",
		"EjEQMA4GA1UEChMHQWNtZSBDbzAgFw03MDAxMDEwMDAwMDBaGA8yMDg0MDEyOTE2",
		"MDAwMFowEjEQMA4GA1UEChMHQWNtZSBDbzCBnzANBgkqhkiG9w0BAQEFAAOBjQAw",
		"gYkCgYEA4mEaF5yWYYrTfMgRXdBpgGnqsHIADQWlw7BIJWD/gNp+fgp4TUZ/7ggV",
		"rrvRORvRFjw14avd9L9EFP7XLi8ViU3uoE1UWI32MlrKqLbGNCXyUIApIoqlbRg6",
		"iErxIk5+ChzFuysQOx01S2yv/ML6dx7NOGHs1S38MUzRZtcXBH8CAwEAAaOBhjCB",
		"gzAOBgNVHQ8BAf8EBAMCAqQwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDwYDVR0TAQH/",
		"BAUwAwEB/zAdBgNVHQ4EFgQUslNI6tYIv909RttHaZVMS/u/VYYwLAYDVR0RBCUw",
		"I4IJbG9jYWxob3N0hwR/AAABhxAAAAAAAAAAAAAAAAAAAAABMA0GCSqGSIb3DQEB",
		"CwUAA4GBAJ2gRpQHr5Qj7dt26bYVMdN4JGXTsvjbVrJfKI0VfPGJ+SUY/uTVBUeX",
		"+Cwv4DFEPBlNx/lzuUkwmRaExC4/w81LWwxe5KltYsjyJuYowiUbLZ6tzLaQ9Bcx",
		"jxClAVvgj90TGYOwsv6ESOX7GWteN1FlD3+jk7vefjFagaKKFYR9",
		"-----END CERTIFICATE-----")
}

func writeKeyPem(tmpDir *TmpFolder) *TmpFile {
	return tmpDir.CreateStringFile("key.pem",
		"-----BEGIN PRIVATE KEY-----",
		"MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBAOJhGheclmGK03zI",
		"EV3QaYBp6rByAA0FpcOwSCVg/4Dafn4KeE1Gf+4IFa670Tkb0RY8NeGr3fS/RBT+",
		"1y4vFYlN7qBNVFiN9jJayqi2xjQl8lCAKSKKpW0YOohK8SJOfgocxbsrEDsdNUts",
		"r/zC+ncezThh7NUt/DFM0WbXFwR/AgMBAAECgYEA1exixstPhI+2+OTrHFc1S4dL",
		"oz+ncqbSlZEBLGl0KWTQQfVM5+FmRR7Yto1/0lLKDBQL6t0J2x3fjWOhHmCaHKZA",
		"VAvZ8+OKxwofih3hlO0tGCB8szUJygp2FAmd0rOUqvPQ+PTohZEUXyDaB8MOIbX+",
		"qoo7g19+VlbyKqmM8HkCQQDs4GQJwEn7GXKllSMyOfiYnjQM2pwsqO0GivXkH+p3",
		"+h5KDp4g3O4EbmbrvZyZB2euVsBjW3pFMu+xPXuOXf91AkEA9KfC7LGLD2OtLmrM",
		"iCZAqHlame+uEEDduDmqjTPnNKUWVeRtYKMF5Hltbeo1jMXMSbVZ+fRWKfQ+HAhQ",
		"xjFJowJAV6U7PqRoe0FSO1QwXrA2fHnk9nCY4qlqckZObyckAVqJhIteFPjKFNeo",
		"u0dAPxsPUOGGc/zwA9Sx/ZmrMuUy1QJBALl7bqawO/Ng6G0mfwZBqgeQaYYHVnnw",
		"E6iV353J2eHpvzNDSUFYlyEOhk4soIindSf0m9CK08Be8a+jBkocF+0CQQC+Hi7L",
		"kZV1slpW82BxYIhs9Gb0OQgK8SsI4aQPTFGUarQXXAm4eRqBO0kaG+jGX6TtW353",
		"EHK784GIxwVXKej/",
		"-----END PRIVATE KEY-----")
}
