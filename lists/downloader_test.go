package lists

import (
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"time"

	. "github.com/0xERR0R/blocky/evt"
	. "github.com/0xERR0R/blocky/helpertest"
	"github.com/0xERR0R/blocky/log"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus/hooks/test"
)

var _ = Describe("Downloader", func() {
	var (
		sut                           *HTTPDownloader
		failedDownloadCountEvtChannel chan string
		loggerHook                    *test.Hook
	)
	BeforeEach(func() {
		failedDownloadCountEvtChannel = make(chan string, 5)
		// collect received events in the channel
		fn := func(url string) {
			failedDownloadCountEvtChannel <- url
		}
		Expect(Bus().Subscribe(CachingFailedDownloadChanged, fn)).Should(Succeed())
		DeferCleanup(func() {
			Expect(Bus().Unsubscribe(CachingFailedDownloadChanged, fn))
		})

		loggerHook = test.NewGlobal()
		log.Log().AddHook(loggerHook)
		DeferCleanup(loggerHook.Reset)
	})

	Describe("Construct downloader", func() {
		When("No options are provided", func() {
			BeforeEach(func() {
				sut = NewDownloader()
			})
			It("Should provide default valus", func() {
				Expect(sut.downloadAttempts).Should(BeNumerically("==", defaultDownloadAttempts))
				Expect(sut.downloadTimeout).Should(BeNumerically("==", defaultDownloadTimeout))
				Expect(sut.downloadCooldown).Should(BeNumerically("==", defaultDownloadCooldown))
			})
		})
		When("Options are provided", func() {
			transport := &http.Transport{}
			BeforeEach(func() {
				sut = NewDownloader(
					WithAttempts(5),
					WithCooldown(2*time.Second),
					WithTimeout(5*time.Second),
					WithTransport(transport),
				)
			})
			It("Should use provided parameters", func() {
				Expect(sut.downloadAttempts).Should(BeNumerically("==", 5))
				Expect(sut.downloadTimeout).Should(BeNumerically("==", 5*time.Second))
				Expect(sut.downloadCooldown).Should(BeNumerically("==", 2*time.Second))
				Expect(sut.httpTransport).Should(BeIdenticalTo(transport))
			})
		})
	})

	Describe("Download of a file", func() {
		var server *httptest.Server
		When("Download was successful", func() {
			BeforeEach(func() {
				server = TestServer("line.one\nline.two")
				DeferCleanup(server.Close)

				sut = NewDownloader()
			})
			It("Should return all lines from the file", func() {
				reader, err := sut.DownloadFile(server.URL)

				Expect(err).Should(Succeed())
				Expect(reader).Should(Not(BeNil()))
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

				sut = NewDownloader(WithAttempts(3))
			})
			It("Should return error", func() {
				reader, err := sut.DownloadFile(server.URL)

				Expect(err).Should(HaveOccurred())
				Expect(reader).Should(BeNil())
				Expect(err.Error()).Should(Equal("got status code 404"))
				Expect(failedDownloadCountEvtChannel).Should(HaveLen(3))
				Expect(failedDownloadCountEvtChannel).Should(Receive(Equal(server.URL)))
			})

		})
		When("Wrong URL is defined", func() {
			BeforeEach(func() {
				sut = NewDownloader()
			})
			It("Should return error", func() {
				_, err := sut.DownloadFile("somewrongurl")

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
				sut = NewDownloader(
					WithTimeout(20*time.Millisecond),
					WithAttempts(3),
					WithCooldown(time.Millisecond))

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
				DeferCleanup(server.Close)

			})
			It("Should perform a retry and return file content", func() {
				reader, err := sut.DownloadFile(server.URL)
				Expect(err).Should(Succeed())
				Expect(reader).Should(Not(BeNil()))
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
				sut = NewDownloader(
					WithTimeout(100*time.Millisecond),
					WithAttempts(3),
					WithCooldown(time.Millisecond))

				// should always produce a timeout
				server = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
					time.Sleep(200 * time.Millisecond)
				}))
				DeferCleanup(server.Close)
			})
			It("Should perform a retry until max retry attempt count is reached and return TransientError", func() {
				reader, err := sut.DownloadFile(server.URL)
				Expect(err).Should(HaveOccurred())
				var transientErr *TransientError
				Expect(errors.As(err, &transientErr)).To(BeTrue())
				Expect(transientErr.Unwrap().Error()).Should(ContainSubstring("Timeout"))
				Expect(reader).Should(BeNil())

				// failed download event was emitted 3 times
				Expect(failedDownloadCountEvtChannel).Should(HaveLen(3))
				Expect(failedDownloadCountEvtChannel).Should(Receive(Equal(server.URL)))
			})
		})
		When("DNS resolution of passed URL fails", func() {
			BeforeEach(func() {
				sut = NewDownloader(
					WithTimeout(100*time.Millisecond),
					WithAttempts(3),
					WithCooldown(time.Millisecond))
			})
			It("Should perform a retry until max retry attempt count is reached and return DNSError", func() {
				reader, err := sut.DownloadFile("http://some.domain.which.does.not.exist")
				Expect(err).Should(HaveOccurred())
				var dnsError *net.DNSError
				Expect(errors.As(err, &dnsError)).To(BeTrue())
				Expect(reader).Should(BeNil())

				// failed download event was emitted 3 times
				Expect(failedDownloadCountEvtChannel).Should(HaveLen(3))
				Expect(failedDownloadCountEvtChannel).Should(Receive(Equal("http://some.domain.which.does.not.exist")))
				Expect(loggerHook.LastEntry().Message).Should(ContainSubstring("Name resolution err: "))
			})
		})
	})
})
