package lists

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http/httptest"
	"os"
	"strings"

	"github.com/0xERR0R/blocky/config"
	. "github.com/0xERR0R/blocky/evt"
	"github.com/0xERR0R/blocky/lists/parsers"
	"github.com/0xERR0R/blocky/log"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	. "github.com/0xERR0R/blocky/helpertest"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("ListCache", func() {
	var (
		tmpDir                         *TmpFolder
		emptyFile, file1, file2, file3 *TmpFile
		server1, server2, server3      *httptest.Server

		sut       *ListCache
		sutConfig config.SourceLoadingConfig

		listCacheType  ListCacheType
		lists          map[string][]config.BytesSource
		downloader     FileDownloader
		mockDownloader *MockDownloader
		ctx            context.Context
		cancelFn       context.CancelFunc
		err            error
		expectFail     bool
	)

	BeforeEach(func() {
		expectFail = false
		ctx, cancelFn = context.WithCancel(context.Background())
		DeferCleanup(cancelFn)

		listCacheType = ListCacheTypeBlacklist

		sutConfig, err = config.WithDefaults[config.SourceLoadingConfig]()
		Expect(err).Should(Succeed())

		sutConfig.RefreshPeriod = -1

		downloader = NewDownloader(config.DownloaderConfig{}, nil)
		mockDownloader = nil

		server1 = TestServer("blocked1.com\nblocked1a.com\n192.168.178.55")
		DeferCleanup(server1.Close)
		server2 = TestServer("blocked2.com")
		DeferCleanup(server2.Close)
		server3 = TestServer("blocked3.com\nblocked1a.com")
		DeferCleanup(server3.Close)

		tmpDir = NewTmpFolder("ListCache")
		Expect(tmpDir.Error).Should(Succeed())
		DeferCleanup(tmpDir.Clean)

		emptyFile = tmpDir.CreateStringFile("empty", "#empty file")
		Expect(emptyFile.Error).Should(Succeed())

		emptyFile = tmpDir.CreateStringFile("empty", "#empty file")
		Expect(emptyFile.Error).Should(Succeed())
		file1 = tmpDir.CreateStringFile("file1", "blocked1.com", "blocked1a.com")
		Expect(file1.Error).Should(Succeed())
		file2 = tmpDir.CreateStringFile("file2", "blocked2.com")
		Expect(file2.Error).Should(Succeed())
		file3 = tmpDir.CreateStringFile("file3", "blocked3.com", "blocked1a.com")
		Expect(file3.Error).Should(Succeed())
	})

	JustBeforeEach(func() {
		Expect(lists).ShouldNot(BeNil(), "bad test: forgot to set `lists`")

		if mockDownloader != nil {
			downloader = mockDownloader
		}

		sut, err = NewListCache(ctx, listCacheType, sutConfig, lists, downloader)
		if expectFail {
			Expect(err).Should(HaveOccurred())
		} else {
			Expect(err).Should(Succeed())
		}
	})

	Describe("List cache and matching", func() {
		When("List is empty", func() {
			BeforeEach(func() {
				lists = map[string][]config.BytesSource{
					"gr0": config.NewBytesSources(emptyFile.Path),
				}
			})

			When("Query with empty", func() {
				It("should not panic", func() {
					group := sut.Match("", []string{"gr0"})
					Expect(group).Should(BeEmpty())
				})
			})

			It("should not match anything", func() {
				group := sut.Match("google.com", []string{"gr1"})
				Expect(group).Should(BeEmpty())
			})
		})
		When("List becomes empty on refresh", func() {
			BeforeEach(func() {
				mockDownloader = newMockDownloader(func(res chan<- string, err chan<- error) {
					res <- "blocked1.com"
					res <- "# nothing"
				})

				lists = map[string][]config.BytesSource{
					"gr1": {mockDownloader.ListSource()},
				}
			})

			It("should delete existing elements from group cache", func(ctx context.Context) {
				group := sut.Match("blocked1.com", []string{"gr1"})
				Expect(group).Should(ContainElement("gr1"))

				err := sut.refresh(ctx)
				Expect(err).Should(Succeed())

				group = sut.Match("blocked1.com", []string{"gr1"})
				Expect(group).Should(BeEmpty())
			})
		})
		When("List has invalid lines", func() {
			BeforeEach(func() {
				lists = map[string][]config.BytesSource{
					"gr1": {
						config.TextBytesSource(
							"inlinedomain1.com",
							"invaliddomain!",
							"inlinedomain2.com",
						),
					},
				}
			})

			It("should still other domains", func() {
				group := sut.Match("inlinedomain1.com", []string{"gr1"})
				Expect(group).Should(ContainElement("gr1"))

				group = sut.Match("inlinedomain2.com", []string{"gr1"})
				Expect(group).Should(ContainElement("gr1"))
			})
		})
		When("a temporary/transient err occurs on download", func() {
			BeforeEach(func() {
				// should produce a transient error on second and third attempt
				mockDownloader = newMockDownloader(func(res chan<- string, err chan<- error) {
					res <- "blocked1.com\nblocked2.com\n"
					err <- &TransientError{inner: errors.New("boom")}
					err <- &TransientError{inner: errors.New("boom")}
				})

				lists = map[string][]config.BytesSource{
					"gr1": {mockDownloader.ListSource()},
				}
			})

			It("should not delete existing elements from group cache", func(ctx context.Context) {
				By("Lists loaded without timeout", func() {
					Eventually(func(g Gomega) {
						group := sut.Match("blocked1.com", []string{"gr1"})
						g.Expect(group).Should(ContainElement("gr1"))
					}, "1s").Should(Succeed())
				})

				Expect(sut.refresh(ctx)).Should(HaveOccurred())

				By("List couldn't be loaded due to timeout", func() {
					group := sut.Match("blocked1.com", []string{"gr1"})
					Expect(group).Should(ContainElement("gr1"))
				})

				_ = sut.Refresh()

				By("List couldn't be loaded due to timeout", func() {
					group := sut.Match("blocked1.com", []string{"gr1"})
					Expect(group).Should(ContainElement("gr1"))
				})
			})
		})
		When("non transient err occurs on download", func() {
			BeforeEach(func() {
				// should produce a non transient error on second attempt
				mockDownloader = newMockDownloader(func(res chan<- string, err chan<- error) {
					res <- "blocked1.com"
					err <- errors.New("boom")
				})

				lists = map[string][]config.BytesSource{
					"gr1": {mockDownloader.ListSource()},
				}
			})

			It("should keep existing elements from group cache", func(ctx context.Context) {
				By("Lists loaded without err", func() {
					group := sut.Match("blocked1.com", []string{"gr1"})
					Expect(group).Should(ContainElement("gr1"))
				})

				Expect(sut.refresh(ctx)).Should(HaveOccurred())

				By("Lists from first load is kept", func() {
					group := sut.Match("blocked1.com", []string{"gr1"})
					Expect(group).Should(ContainElement("gr1"))
				})
			})
		})
		When("Configuration has 3 external working urls", func() {
			BeforeEach(func() {
				lists = map[string][]config.BytesSource{
					"gr1": config.NewBytesSources(server1.URL, server2.URL),
					"gr2": config.NewBytesSources(server3.URL),
				}
			})

			It("should download the list and match against", func() {
				group := sut.Match("blocked1.com", []string{"gr1", "gr2"})
				Expect(group).Should(ContainElement("gr1"))

				group = sut.Match("blocked1a.com", []string{"gr1", "gr2"})
				Expect(group).Should(ContainElement("gr1"))

				group = sut.Match("blocked1a.com", []string{"gr2"})
				Expect(group).Should(ContainElement("gr2"))
			})
		})
		When("Configuration has some faulty urls", func() {
			BeforeEach(func() {
				lists = map[string][]config.BytesSource{
					"gr1": config.NewBytesSources(server1.URL, server2.URL, "doesnotexist"),
					"gr2": config.NewBytesSources(server3.URL, "someotherfile"),
				}
			})

			It("should download the list and match against", func() {
				group := sut.Match("blocked1.com", []string{"gr1", "gr2"})
				Expect(group).Should(ContainElement("gr1"))

				group = sut.Match("blocked1a.com", []string{"gr1", "gr2"})
				Expect(group).Should(ContainElements("gr1", "gr2"))

				group = sut.Match("blocked1a.com", []string{"gr2"})
				Expect(group).Should(ContainElement("gr2"))
			})
		})
		When("List will be updated", func() {
			resultCnt := 0

			BeforeEach(func() {
				lists = map[string][]config.BytesSource{
					"gr1": config.NewBytesSources(server1.URL),
				}

				_ = Bus().SubscribeOnce(BlockingCacheGroupChanged, func(listType ListCacheType, group string, cnt int) {
					resultCnt = cnt
				})
			})

			It("event should be fired and contain count of elements in downloaded lists", func() {
				group := sut.Match("blocked1.com", []string{})
				Expect(group).Should(BeEmpty())
				Expect(resultCnt).Should(Equal(3))
			})
		})
		When("multiple groups are passed", func() {
			BeforeEach(func() {
				lists = map[string][]config.BytesSource{
					"gr1": config.NewBytesSources(file1.Path, file2.Path),
					"gr2": config.NewBytesSources("file://" + file3.Path),
				}
			})

			It("should match", func() {
				Expect(sut.groupedCache.ElementCount("gr1")).Should(Equal(3))
				Expect(sut.groupedCache.ElementCount("gr2")).Should(Equal(2))

				group := sut.Match("blocked1.com", []string{"gr1", "gr2"})
				Expect(group).Should(ContainElement("gr1"))

				group = sut.Match("blocked1a.com", []string{"gr1", "gr2"})
				Expect(group).Should(ContainElement("gr1"))

				group = sut.Match("blocked1a.com", []string{"gr2"})
				Expect(group).Should(ContainElement("gr2"))
			})
		})
		When("group with bigger files", func() {
			var (
				file1, file2, file3    string
				lines1, lines2, lines3 int
			)
			BeforeEach(func() {
				file1, lines1 = createTestListFile(GinkgoT().TempDir(), 10000)
				file2, lines2 = createTestListFile(GinkgoT().TempDir(), 15000)
				file3, lines3 = createTestListFile(GinkgoT().TempDir(), 13000)
				lists = map[string][]config.BytesSource{
					"gr1": config.NewBytesSources(file1, file2, file3),
				}
			})
			It("should match", func() {
				sut, err = NewListCache(ctx, ListCacheTypeBlacklist, sutConfig, lists, downloader)
				Expect(err).Should(Succeed())

				Expect(sut.groupedCache.ElementCount("gr1")).Should(Equal(lines1 + lines2 + lines3))
			})
		})
		When("inline list content is defined", func() {
			BeforeEach(func() {
				lists = map[string][]config.BytesSource{
					"gr1": {config.TextBytesSource(
						"inlinedomain1.com",
						"#some comment",
						"inlinedomain2.com",
					)},
				}
			})

			It("should match", func() {
				Expect(sut.groupedCache.ElementCount("gr1")).Should(Equal(2))
				group := sut.Match("inlinedomain1.com", []string{"gr1"})
				Expect(group).Should(ContainElement("gr1"))

				group = sut.Match("inlinedomain2.com", []string{"gr1"})
				Expect(group).Should(ContainElement("gr1"))
			})
		})
		When("Text file can't be parsed", func() {
			BeforeEach(func() {
				lists = map[string][]config.BytesSource{
					"gr1": {
						config.TextBytesSource(
							"inlinedomain1.com",
							"lineTooLong"+strings.Repeat("x", bufio.MaxScanTokenSize), // too long
						),
					},
				}
			})

			It("should still match already imported strings", func() {
				group := sut.Match("inlinedomain1.com", []string{"gr1"})
				Expect(group).Should(ContainElement("gr1"))
			})
		})
		When("Text file has too many errors", func() {
			BeforeEach(func() {
				sutConfig.MaxErrorsPerSource = 0
				sutConfig.Strategy = config.StartStrategyTypeFailOnError
				lists = map[string][]config.BytesSource{
					"gr1": {
						config.TextBytesSource("invaliddomain!"), // too many errors since `maxErrorsPerSource` is 0
					},
				}
				expectFail = true
			})
			It("should fail parsing", func() {
				Expect(err).Should(MatchError(parsers.ErrTooManyErrors))
			})
		})
		When("file has end of line comment", func() {
			BeforeEach(func() {
				lists = map[string][]config.BytesSource{
					"gr1": {config.TextBytesSource("inlinedomain1.com#a comment")},
				}
			})

			It("should still parse the domain", func() {
				group := sut.Match("inlinedomain1.com", []string{"gr1"})
				Expect(group).Should(ContainElement("gr1"))
			})
		})
		When("inline regex content is defined", func() {
			BeforeEach(func() {
				lists = map[string][]config.BytesSource{
					"gr1": {config.TextBytesSource("/^apple\\.(de|com)$/")},
				}
			})

			It("should match", func() {
				group := sut.Match("apple.com", []string{"gr1"})
				Expect(group).Should(ContainElement("gr1"))

				group = sut.Match("apple.de", []string{"gr1"})
				Expect(group).Should(ContainElement("gr1"))
			})
		})
	})
	Describe("LogConfig", func() {
		var (
			logger *logrus.Entry
			hook   *log.MockLoggerHook
		)

		BeforeEach(func() {
			logger, hook = log.NewMockEntry()

			lists = map[string][]config.BytesSource{
				"gr1": config.NewBytesSources(server1.URL, server2.URL),
				"gr2": {config.TextBytesSource("inline", "definition")},
			}
		})

		It("should print list configuration", func() {
			sut, err = NewListCache(ctx, ListCacheTypeBlacklist, sutConfig, lists, downloader)
			Expect(err).Should(Succeed())

			sut.LogConfig(logger)
			Expect(hook.Calls).ShouldNot(BeEmpty())
			Expect(hook.Messages).Should(ContainElement(ContainSubstring("gr1:")))
			Expect(hook.Messages).Should(ContainElement(ContainSubstring("gr2:")))
			Expect(hook.Messages).Should(ContainElement(ContainSubstring("TOTAL:")))
		})
	})

	Describe("StartStrategy", func() {
		When("async load is enabled", func() {
			BeforeEach(func() {
				sutConfig.Strategy = config.StartStrategyTypeFast

				lists = map[string][]config.BytesSource{
					"gr1": config.NewBytesSources("doesnotexist"),
				}
			})

			It("should never return an error", func() {
				_, err := NewListCache(ctx, ListCacheTypeBlacklist, sutConfig, lists, downloader)
				Expect(err).Should(Succeed())
			})
		})
	})
})

type MockDownloader struct {
	MockCallSequence[string]
}

func newMockDownloader(driver func(res chan<- string, err chan<- error)) *MockDownloader {
	return &MockDownloader{NewMockCallSequence(driver)}
}

func (m *MockDownloader) DownloadFile(_ string) (io.ReadCloser, error) {
	str, err := m.Call()
	if err != nil {
		return nil, err
	}

	return io.NopCloser(strings.NewReader(str)), nil
}

func (m *MockDownloader) ListSource() config.BytesSource {
	return config.BytesSource{
		Type: config.BytesSourceTypeHttp,
		From: "http://mock-downloader",
	}
}

func createTestListFile(dir string, totalLines int) (string, int) {
	file, err := os.CreateTemp(dir, "blocky")
	if err != nil {
		log.Log().Fatal(err)
	}

	w := bufio.NewWriter(file)
	for i := 0; i < totalLines; i++ {
		fmt.Fprintln(w, uuid.NewString()+".com")
	}
	w.Flush()

	return file.Name(), totalLines
}
