package lists

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"time"

	"github.com/0xERR0R/blocky/config"
	. "github.com/0xERR0R/blocky/evt"
	. "github.com/0xERR0R/blocky/helpertest"
	"github.com/0xERR0R/blocky/log"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus/hooks/test"
)

var _ = Describe("Downloader", func() {
	var (
		sutConfig                     config.Downloader
		sut                           *httpDownloader
		failedDownloadCountEvtChannel chan string
		loggerHook                    *test.Hook
	)
	BeforeEach(func() {
		var err error

		sutConfig, err = config.WithDefaults[config.Downloader]()
		Expect(err).Should(Succeed())

		failedDownloadCountEvtChannel = make(chan string, 5)
		// collect received events in the channel
		fn := func(url string) {
			failedDownloadCountEvtChannel <- url
		}
		Expect(Bus().Subscribe(CachingFailedDownloadChanged, fn)).Should(Succeed())
		DeferCleanup(func() {
			Expect(Bus().Unsubscribe(CachingFailedDownloadChanged, fn)).Should(Succeed())
		})

		loggerHook = test.NewGlobal()
		log.Log().AddHook(loggerHook)
		DeferCleanup(loggerHook.Reset)
	})

	JustBeforeEach(func() {
		sut = newDownloader(sutConfig, nil)
	})

	Describe("NewDownloader", func() {
		It("Should use provided parameters", func() {
			transport := new(http.Transport)

			sut = NewDownloader(
				config.Downloader{
					Attempts: 5,
					Cooldown: config.Duration(2 * time.Second),
					Timeout:  config.Duration(5 * time.Second),
				},
				transport,
			).(*httpDownloader)

			Expect(sut.cfg.Attempts).Should(BeNumerically("==", 5))
			Expect(sut.cfg.Timeout).Should(BeNumerically("==", 5*time.Second))
			Expect(sut.cfg.Cooldown).Should(BeNumerically("==", 2*time.Second))
			Expect(sut.client.Transport).Should(BeIdenticalTo(transport))
		})
	})

	Describe("Download of a file", func() {
		var server *httptest.Server
		When("Download was successful", func() {
			BeforeEach(func() {
				server = TestServer("line.one\nline.two")
				sut = newDownloader(sutConfig, nil)
			})
			It("Should return all lines from the file", func(ctx context.Context) {
				reader, err := sut.DownloadFile(ctx, server.URL)

				Expect(err).Should(Succeed())
				Expect(reader).ShouldNot(BeNil())
				DeferCleanup(reader.Close)
				buf := new(strings.Builder)
				_, err = io.Copy(buf, reader)
				Expect(err).Should(Succeed())
				Expect(buf.String()).Should(Equal("line.one\nline.two"))
			})
		})
		When("Server returns NOT_FOUND (404)", func() {
			BeforeEach(func() {
				server = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
					rw.WriteHeader(http.StatusNotFound)
				}))
				DeferCleanup(server.Close)

				sutConfig.Attempts = 3
			})
			It("Should return error without retrying (permanent error)", func(ctx context.Context) {
				reader, err := sut.DownloadFile(ctx, server.URL)

				Expect(err).Should(HaveOccurred())
				Expect(reader).Should(BeNil())
				Expect(err.Error()).Should(ContainSubstring("permanent error: status code 404"))
				// Permanent errors should not retry, so only 1 failed download event
				Expect(failedDownloadCountEvtChannel).Should(HaveLen(1))
				Expect(failedDownloadCountEvtChannel).Should(Receive(Equal(server.URL)))
			})
		})
		When("Wrong URL is defined", func() {
			BeforeEach(func() {
				sutConfig.Attempts = 1
			})
			It("Should return error", func(ctx context.Context) {
				_, err := sut.DownloadFile(ctx, "somewrongurl")

				Expect(err).Should(HaveOccurred())
				Expect(loggerHook.LastEntry().Message).Should(ContainSubstring("Can't download file: "))
				// failed download event was emitted only once
				Expect(failedDownloadCountEvtChannel).Should(HaveLen(1))
				Expect(failedDownloadCountEvtChannel).Should(Receive(Equal("somewrongurl")))
			})
		})

		When("If timeout occurs on first request", func() {
			var attempt uint64 = 1

			BeforeEach(func() {
				sutConfig = config.Downloader{
					Timeout:  config.Duration(20 * time.Millisecond),
					Attempts: 3,
					Cooldown: config.Duration(time.Millisecond),
				}

				// should produce a timeout on first attempt
				server = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
					a := atomic.LoadUint64(&attempt)
					atomic.AddUint64(&attempt, 1)
					if a == 1 {
						time.Sleep(500 * time.Millisecond)
					} else {
						_, err := rw.Write([]byte("blocked1.com"))
						Expect(err).Should(Succeed())
					}
				}))
			})
			It("Should perform a retry and return file content", func(ctx context.Context) {
				reader, err := sut.DownloadFile(ctx, server.URL)
				Expect(err).Should(Succeed())
				Expect(reader).ShouldNot(BeNil())
				DeferCleanup(reader.Close)

				buf := new(strings.Builder)
				_, err = io.Copy(buf, reader)
				Expect(err).Should(Succeed())
				Expect(buf.String()).Should(Equal("blocked1.com"))

				// failed download event was emitted only once
				Expect(failedDownloadCountEvtChannel).Should(HaveLen(1))
				Expect(failedDownloadCountEvtChannel).Should(Receive(Equal(server.URL)))
				Expect(loggerHook.LastEntry().Message).Should(ContainSubstring("Temporary network err / Timeout occurred: "))
			})
		})
		When("If timeout occurs on all request", func() {
			BeforeEach(func() {
				sutConfig = config.Downloader{
					Timeout:  config.Duration(10 * time.Millisecond),
					Attempts: 3,
					Cooldown: config.Duration(time.Millisecond),
				}

				// should always produce a timeout
				server = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
					time.Sleep(20 * time.Millisecond)
				}))
			})
			It("Should perform a retry until max retry attempt count is reached and return TransientError",
				func(ctx context.Context) {
					reader, err := sut.DownloadFile(ctx, server.URL)
					Expect(err).Should(HaveOccurred())
					Expect(errors.As(err, new(*TransientError))).Should(BeTrue())
					Expect(err.Error()).Should(ContainSubstring("Timeout"))
					Expect(reader).Should(BeNil())

					// failed download event was emitted 3 times
					Expect(failedDownloadCountEvtChannel).Should(HaveLen(3))
					Expect(failedDownloadCountEvtChannel).Should(Receive(Equal(server.URL)))
				})
		})
		When("DNS resolution of passed URL fails", func() {
			BeforeEach(func() {
				sutConfig = config.Downloader{
					Timeout:  config.Duration(2 * time.Second),
					Attempts: 3,
					Cooldown: 200 * config.Duration(time.Millisecond),
				}
			})
			It("Should perform a retry until max retry attempt count is reached and return DNS-related error",
				func(ctx context.Context) {
					reader, err := sut.DownloadFile(ctx, "http://xyz.example.com")
					Expect(err).Should(HaveOccurred())

					// Check if it's a DNS error or contains DNS-related message
					var dnsError *net.DNSError
					isDNSError := errors.As(err, &dnsError)
					containsDNSErrorMessage := strings.Contains(strings.ToLower(err.Error()), "lookup") ||
						strings.Contains(strings.ToLower(err.Error()), "dns") ||
						strings.Contains(strings.ToLower(err.Error()), "resolve") ||
						strings.Contains(strings.ToLower(err.Error()), "unknown host")

					Expect(isDNSError || containsDNSErrorMessage).Should(BeTrue(),
						"expected DNS-related error, got: %v", err)
					Expect(reader).Should(BeNil())

					// failed download event was emitted 3 times
					Expect(failedDownloadCountEvtChannel).Should(HaveLen(3))
					Expect(failedDownloadCountEvtChannel).Should(Receive(Equal("http://xyz.example.com")))

					// Use Or() to combine matchers instead of the | operator
					Expect(loggerHook.LastEntry().Message).Should(Or(
						ContainSubstring("Can't download file:"),
						ContainSubstring("Name resolution err:")))
				})
		})
		When("a proxy is configured", func() {
			It("should be used", func(ctx context.Context) {
				proxy := TestHTTPProxy()

				sut.client.Transport = &http.Transport{Proxy: proxy.ReqURL}

				_, err := sut.DownloadFile(ctx, "http://example.com")
				Expect(err).Should(HaveOccurred())

				Expect(proxy.RequestTarget()).Should(Equal("example.com"))
			})
		})

		When("Server returns GONE (410)", func() {
			BeforeEach(func() {
				server = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
					rw.WriteHeader(http.StatusGone)
				}))
				DeferCleanup(server.Close)

				sutConfig.Attempts = 3
			})
			It("Should return error without retrying (permanent error)", func(ctx context.Context) {
				reader, err := sut.DownloadFile(ctx, server.URL)

				Expect(err).Should(HaveOccurred())
				Expect(reader).Should(BeNil())
				Expect(err.Error()).Should(ContainSubstring("permanent error: status code 410"))
				// Permanent errors should not retry
				Expect(failedDownloadCountEvtChannel).Should(HaveLen(1))
			})
		})

		When("Server returns TOO_MANY_REQUESTS (429)", func() {
			var attemptCount atomic.Uint64

			BeforeEach(func() {
				attemptCount.Store(0)
				server = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
					count := attemptCount.Add(1)
					if count < 3 {
						rw.WriteHeader(http.StatusTooManyRequests)
					} else {
						_, err := rw.Write([]byte("success after rate limit"))
						Expect(err).Should(Succeed())
					}
				}))
				DeferCleanup(server.Close)

				sutConfig.Attempts = 3
				sutConfig.Cooldown = config.Duration(10 * time.Millisecond)
				sutConfig.MaxBackoff = config.Duration(100 * time.Millisecond)
			})
			It("Should retry with exponential backoff and eventually succeed", func(ctx context.Context) {
				reader, err := sut.DownloadFile(ctx, server.URL)

				Expect(err).Should(Succeed())
				Expect(reader).ShouldNot(BeNil())
				DeferCleanup(reader.Close)

				buf := new(strings.Builder)
				_, err = io.Copy(buf, reader)
				Expect(err).Should(Succeed())
				Expect(buf.String()).Should(Equal("success after rate limit"))

				// Should have retried 2 times before succeeding
				Expect(failedDownloadCountEvtChannel).Should(HaveLen(2))
			})
		})

		When("Server returns SERVICE_UNAVAILABLE (503)", func() {
			var attemptCount atomic.Uint64

			BeforeEach(func() {
				attemptCount.Store(0)
				server = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
					count := attemptCount.Add(1)
					if count < 2 {
						rw.WriteHeader(http.StatusServiceUnavailable)
					} else {
						_, err := rw.Write([]byte("service restored"))
						Expect(err).Should(Succeed())
					}
				}))
				DeferCleanup(server.Close)

				sutConfig.Attempts = 3
				sutConfig.Cooldown = config.Duration(10 * time.Millisecond)
			})
			It("Should retry and succeed when service is restored", func(ctx context.Context) {
				reader, err := sut.DownloadFile(ctx, server.URL)

				Expect(err).Should(Succeed())
				Expect(reader).ShouldNot(BeNil())
				DeferCleanup(reader.Close)

				buf := new(strings.Builder)
				_, err = io.Copy(buf, reader)
				Expect(err).Should(Succeed())
				Expect(buf.String()).Should(Equal("service restored"))
			})
		})

		When("Server returns BAD_GATEWAY (502)", func() {
			BeforeEach(func() {
				server = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
					rw.WriteHeader(http.StatusBadGateway)
				}))
				DeferCleanup(server.Close)

				sutConfig.Attempts = 3
				sutConfig.Cooldown = config.Duration(10 * time.Millisecond)
			})
			It("Should retry transient gateway errors", func(ctx context.Context) {
				reader, err := sut.DownloadFile(ctx, server.URL)

				Expect(err).Should(HaveOccurred())
				Expect(reader).Should(BeNil())
				Expect(err.Error()).Should(ContainSubstring("transient error: status code 502"))
				// Should retry all 3 attempts
				Expect(failedDownloadCountEvtChannel).Should(HaveLen(3))
			})
		})

		When("Exponential backoff is used", func() {
			var requestTimes []time.Time

			BeforeEach(func() {
				requestTimes = make([]time.Time, 0)
				server = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
					requestTimes = append(requestTimes, time.Now())
					rw.WriteHeader(http.StatusServiceUnavailable)
				}))
				DeferCleanup(server.Close)

				sutConfig.Attempts = 3
				sutConfig.Cooldown = config.Duration(100 * time.Millisecond)
				sutConfig.MaxBackoff = config.Duration(time.Second)
			})
			It("Should increase delay between retries", func(ctx context.Context) {
				_, err := sut.DownloadFile(ctx, server.URL)

				Expect(err).Should(HaveOccurred())
				Expect(requestTimes).Should(HaveLen(3))

				// Check that delays are increasing (with some tolerance for timing)
				if len(requestTimes) >= 3 {
					delay1 := requestTimes[1].Sub(requestTimes[0])
					delay2 := requestTimes[2].Sub(requestTimes[1])

					// Second delay should be longer than first (exponential backoff)
					// Using 50ms tolerance for test timing variance
					Expect(delay2).Should(BeNumerically(">", delay1-50*time.Millisecond))
				}
			})
		})

		When("Testing drainAndClose helper", func() {
			It("Should properly drain and close response body", func() {
				server = TestServer("test content that should be drained")
				DeferCleanup(server.Close)

				req, err := http.NewRequest(http.MethodGet, server.URL, nil)
				Expect(err).Should(Succeed())

				resp, err := sut.client.Do(req)
				Expect(err).Should(Succeed())

				// This should not panic and should properly clean up
				Expect(func() {
					drainAndClose(resp.Body)
				}).ShouldNot(Panic())
			})
		})
	})
})
