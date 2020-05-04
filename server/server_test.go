package server

import (
	"blocky/api"
	"blocky/config"
	. "blocky/helpertest"
	"blocky/resolver"
	"blocky/util"
	"bytes"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

var _ = Describe("Running DNS server", func() {
	Describe("performing DNS request with running server", func() {
		var (
			upstreamGoogle, upstreamFritzbox, upstreamClient config.Upstream
			mockClientName                                   string
			sut                                              *Server
			err                                              error
			resp                                             *dns.Msg
		)

		BeforeSuite(func() {
			upstreamGoogle = resolver.TestUDPUpstream(func(request *dns.Msg) *dns.Msg {
				response, err := util.NewMsgWithAnswer(util.ExtractDomain(request.Question[0]), 123, dns.TypeA, "123.124.122.122")

				Expect(err).Should(Succeed())
				return response
			})
			upstreamFritzbox = resolver.TestUDPUpstream(func(request *dns.Msg) *dns.Msg {
				response, err := util.NewMsgWithAnswer(util.ExtractDomain(request.Question[0]), 3600, dns.TypeA, "192.168.178.2")

				Expect(err).Should(Succeed())
				return response
			})

			upstreamClient = resolver.TestUDPUpstream(func(request *dns.Msg) *dns.Msg {
				response, err := util.NewMsgWithAnswer(util.ExtractDomain(request.Question[0]), 3600, dns.TypePTR, mockClientName)

				Expect(err).Should(Succeed())
				return response
			})

			// create server
			sut, err = NewServer(&config.Config{
				CustomDNS: config.CustomDNSConfig{
					Mapping: map[string]net.IP{
						"custom.lan": net.ParseIP("192.168.178.55"),
						"lan.home":   net.ParseIP("192.168.178.56"),
					},
				},
				Conditional: config.ConditionalUpstreamConfig{
					Mapping: map[string]config.Upstream{"fritz.box": upstreamFritzbox},
				},
				Blocking: config.BlockingConfig{
					BlackLists: map[string][]string{
						"ads": {
							"../testdata/doubleclick.net.txt",
							"../testdata/www.bild.de.txt",
							"../testdata/heise.de.txt"},
						"youtube": {"../testdata/youtube.com.txt"}},
					WhiteLists: map[string][]string{
						"ads":       {"../testdata/heise.de.txt"},
						"whitelist": {"../testdata/heise.de.txt"},
					},
					ClientGroupsBlock: map[string][]string{
						"default":         {"ads"},
						"clWhitelistOnly": {"whitelist"},
						"clAdsAndYoutube": {"ads", "youtube"},
						"clYoutubeOnly":   {"youtube"},
					},
				},
				Upstream: config.UpstreamConfig{
					ExternalResolvers: []config.Upstream{upstreamGoogle},
				},
				ClientLookup: config.ClientLookupConfig{
					Upstream: upstreamClient,
				},

				Port:     55555,
				HTTPPort: 4000,
				Prometheus: config.PrometheusConfig{
					Enable: true,
					Path:   "/metrics",
				},
			})

			Expect(err).Should(Succeed())

			// start server
			go func() {
				sut.Start()
			}()
			time.Sleep(100 * time.Millisecond)
		})

		AfterSuite(func() {
			sut.Stop()
		})

		BeforeEach(func() {
			mockClientName = ""
			// reset client cache
			res := sut.queryResolver
			for res != nil {
				if t, ok := res.(*resolver.ClientNamesResolver); ok {
					t.FlushCache()
					break
				}
				if c, ok := res.(resolver.ChainedResolver); ok {
					res = c.GetNext()
				} else {
					break
				}
			}
		})

		AfterEach(func() {
			Expect(resp.Rcode).Should(Equal(dns.RcodeSuccess))
		})
		Context("DNS query is resolvable via external DNS", func() {
			It("should return valid answer", func() {
				resp = requestServer(util.NewMsgWithQuestion("google.de.", dns.TypeA))

				Expect(resp.Answer).Should(BeDNSRecord("google.de.", dns.TypeA, 123, "123.124.122.122"))
			})
		})
		Context("Custom DNS entry with exact match", func() {
			It("should return valid answer", func() {
				resp = requestServer(util.NewMsgWithQuestion("custom.lan.", dns.TypeA))

				Expect(resp.Answer).Should(BeDNSRecord("custom.lan.", dns.TypeA, 3600, "192.168.178.55"))
			})
		})
		Context("Custom DNS entry with sub domain", func() {
			It("should return valid answer", func() {
				resp = requestServer(util.NewMsgWithQuestion("host.lan.home.", dns.TypeA))

				Expect(resp.Answer).Should(BeDNSRecord("host.lan.home.", dns.TypeA, 3600, "192.168.178.56"))
			})
		})
		Context("Conditional upstream", func() {
			It("should resolve query via conditional upstream resolver", func() {
				resp = requestServer(util.NewMsgWithQuestion("host.fritz.box.", dns.TypeA))

				Expect(resp.Answer).Should(BeDNSRecord("host.fritz.box.", dns.TypeA, 3600, "192.168.178.2"))
			})
		})
		Context("Blocking default group", func() {
			It("Query should be blocked, domain is in default group", func() {
				resp = requestServer(util.NewMsgWithQuestion("doubleclick.net.", dns.TypeA))

				Expect(resp.Answer).Should(BeDNSRecord("doubleclick.net.", dns.TypeA, 21600, "0.0.0.0"))
			})
		})
		Context("Blocking default group with sub domain", func() {
			It("Query with subdomain should be blocked, domain is in default group", func() {
				resp = requestServer(util.NewMsgWithQuestion("www.bild.de.", dns.TypeA))

				Expect(resp.Answer).Should(BeDNSRecord("www.bild.de.", dns.TypeA, 21600, "0.0.0.0"))
			})
		})
		Context("no blocking default group with sub domain", func() {
			It("Query with should not be blocked, sub domain is not in blacklist", func() {
				resp = requestServer(util.NewMsgWithQuestion("bild.de.", dns.TypeA))

				Expect(resp.Answer).Should(BeDNSRecord("bild.de.", dns.TypeA, 0, "123.124.122.122"))
			})
		})
		Context("domain is on white and blacklist default group", func() {
			It("Query with should not be blocked, domain is on white and blacklist", func() {
				resp = requestServer(util.NewMsgWithQuestion("heise.de.", dns.TypeA))

				Expect(resp.Answer).Should(BeDNSRecord("heise.de.", dns.TypeA, 0, "123.124.122.122"))
			})
		})
		Context("domain is on client specific white list", func() {
			It("Query with should not be blocked, domain is on client's white list", func() {
				mockClientName = "clWhitelistOnly"
				resp = requestServer(util.NewMsgWithQuestion("heise.de.", dns.TypeA))

				Expect(resp.Answer).Should(BeDNSRecord("heise.de.", dns.TypeA, 0, "123.124.122.122"))
			})
		})
		Context("block client whitelist only", func() {
			It("Query with should be blocked, client has only whitelist, domain is not on client's white list", func() {
				mockClientName = "clWhitelistOnly"
				resp = requestServer(util.NewMsgWithQuestion("google.de.", dns.TypeA))

				Expect(resp.Answer).Should(BeDNSRecord("google.de.", dns.TypeA, 0, "0.0.0.0"))
			})
		})
		Context("block client with 2 groups", func() {
			It("Query with should be blocked, domain is on black list", func() {
				mockClientName = "clAdsAndYoutube"
				resp = requestServer(util.NewMsgWithQuestion("www.bild.de.", dns.TypeA))

				Expect(resp.Answer).Should(BeDNSRecord("www.bild.de.", dns.TypeA, 0, "0.0.0.0"))

				resp = requestServer(util.NewMsgWithQuestion("youtube.com.", dns.TypeA))

				Expect(resp.Answer).Should(BeDNSRecord("youtube.com.", dns.TypeA, 0, "0.0.0.0"))
			})
		})
		Context("client with 1 group: no block if domain in other group", func() {
			It("Query with should not be blocked, domain is on black list in another group", func() {
				mockClientName = "clYoutubeOnly"
				resp = requestServer(util.NewMsgWithQuestion("www.bild.de.", dns.TypeA))

				Expect(resp.Answer).Should(BeDNSRecord("www.bild.de.", dns.TypeA, 0, "123.124.122.122"))
			})
		})
		Context("block client with 1 group", func() {
			It("Query with should not  blocked, domain is on black list in client's group", func() {
				mockClientName = "clYoutubeOnly"
				resp = requestServer(util.NewMsgWithQuestion("youtube.com.", dns.TypeA))

				Expect(resp.Answer).Should(BeDNSRecord("youtube.com.", dns.TypeA, 0, "0.0.0.0"))
			})
		})
		Context("health check", func() {
			It("Should always return dummy response", func() {
				resp = requestServer(util.NewMsgWithQuestion("healthcheck.blocky.", dns.TypeA))

				Expect(resp.Answer).Should(BeEmpty())
			})
		})

	})

	Describe("Swagger endpoint", func() {
		When("Swagger URL is called", func() {
			It("should serve swagger page", func() {
				r, err := http.Get("http://localhost:4000/swagger/")
				Expect(err).Should(Succeed())
				Expect(r.StatusCode).Should(Equal(http.StatusOK))
			})
		})
	})
	Describe("Prometheus endpoint", func() {
		When("Prometheus URL is called", func() {
			It("should return prometheus data", func() {
				r, err := http.Get("http://localhost:4000/metrics")
				Expect(err).Should(Succeed())
				Expect(r.StatusCode).Should(Equal(http.StatusOK))
			})
		})
	})
	Describe("Root endpoint", func() {
		When("Root URL is called", func() {
			It("should return root page", func() {
				r, err := http.Get("http://localhost:4000/")
				Expect(err).Should(Succeed())
				Expect(r.StatusCode).Should(Equal(http.StatusOK))
			})
		})
	})

	Describe("Query Rest API", func() {
		When("Query API is called", func() {
			It("Should process the query", func() {
				req := api.QueryRequest{
					Query: "google.de",
					Type:  "A",
				}
				jsonValue, _ := json.Marshal(req)

				resp, err := http.Post("http://localhost:4000/api/query", "application/json", bytes.NewBuffer(jsonValue))

				Expect(err).Should(Succeed())
				defer resp.Body.Close()

				Expect(resp.StatusCode).Should(Equal(http.StatusOK))

				var result api.QueryResult
				err = json.NewDecoder(resp.Body).Decode(&result)
				Expect(err).Should(Succeed())
				Expect(result.Response).Should(Equal("A (123.124.122.122)"))
			})
		})
		When("Wrong request type is used", func() {
			It("Should return internal error", func() {
				req := api.QueryRequest{
					Query: "google.de",
					Type:  "WrongTyoe",
				}
				jsonValue, _ := json.Marshal(req)

				resp, err := http.Post("http://localhost:4000/api/query", "application/json", bytes.NewBuffer(jsonValue))

				Expect(err).Should(Succeed())
				defer resp.Body.Close()

				Expect(resp.StatusCode).Should(Equal(http.StatusInternalServerError))
			})
		})
		When("Request is malformed", func() {
			It("Should return internal error", func() {
				jsonValue := []byte("")

				resp, err := http.Post("http://localhost:4000/api/query", "application/json", bytes.NewBuffer(jsonValue))

				Expect(err).Should(Succeed())
				defer resp.Body.Close()

				Expect(resp.StatusCode).Should(Equal(http.StatusInternalServerError))
			})
		})
	})

	Describe("Server start", func() {
		When("Server start is called", func() {
			It("start was called 2 times, start should fail", func() {
				defer func() { logrus.StandardLogger().ExitFunc = nil }()

				var fatal bool

				logrus.StandardLogger().ExitFunc = func(int) { fatal = true }

				// create server
				server, err := NewServer(&config.Config{
					CustomDNS: config.CustomDNSConfig{
						Mapping: map[string]net.IP{
							"custom.lan": net.ParseIP("192.168.178.55"),
							"lan.home":   net.ParseIP("192.168.178.56"),
						},
					},

					Port: 55556,
				})

				Expect(err).Should(Succeed())

				// start server
				go func() {
					server.Start()
				}()

				defer server.Stop()

				time.Sleep(100 * time.Millisecond)

				Expect(fatal).Should(BeFalse())

				// start again -> should fail
				server.Start()

				time.Sleep(100 * time.Millisecond)

				Expect(fatal).Should(BeTrue())
			})
		})
	})
	Describe("Server stop", func() {
		When("Stop is called", func() {
			It("stop was called 2 times, start should fail", func() {
				defer func() { logrus.StandardLogger().ExitFunc = nil }()

				var fatal bool

				logrus.StandardLogger().ExitFunc = func(int) { fatal = true }

				// create server
				server, err := NewServer(&config.Config{
					CustomDNS: config.CustomDNSConfig{
						Mapping: map[string]net.IP{
							"custom.lan": net.ParseIP("192.168.178.55"),
							"lan.home":   net.ParseIP("192.168.178.56"),
						},
					},

					Port: 55557,
				})

				Expect(err).Should(Succeed())

				// start server
				go func() {
					server.Start()
				}()

				defer server.Stop()

				time.Sleep(100 * time.Millisecond)

				server.Stop()

				// stop server, should be ok
				Expect(fatal).Should(BeFalse())

				// stop again, should raise fatal error
				server.Stop()

				Expect(fatal).Should(BeTrue())
			})
		})
	})

	Describe("resolve client IP", func() {
		Context("UDP address", func() {
			It("should correct resolve client IP", func() {
				ip := resolveClientIP(&net.UDPAddr{IP: net.ParseIP("192.168.178.88")})
				Expect(ip).Should(Equal(net.ParseIP("192.168.178.88")))
			})
		})
		Context("TCP address", func() {
			It("should correct resolve client IP", func() {
				ip := resolveClientIP(&net.TCPAddr{IP: net.ParseIP("192.168.178.88")})
				Expect(ip).Should(Equal(net.ParseIP("192.168.178.88")))
			})
		})
	})

})

func requestServer(request *dns.Msg) *dns.Msg {
	conn, err := net.Dial("udp", ":55555")
	if err != nil {
		log.Fatal("could not connect to server: ", err)
	}
	defer conn.Close()

	msg, err := request.Pack()
	if err != nil {
		log.Fatal("can't pack request: ", err)
	}

	_, err = conn.Write(msg)
	if err != nil {
		log.Fatal("can't send request to server: ", err)
	}

	out := make([]byte, 1024)

	if _, err := conn.Read(out); err == nil {
		response := new(dns.Msg)
		err := response.Unpack(out)

		if err != nil {
			log.Fatal("can't unpack response: ", err)
		}

		return response
	}

	log.Fatal("could not read from connection", err)

	return nil
}
