package lists

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http/httptest"
	"os"
	"strings"
	"time"

	. "github.com/0xERR0R/blocky/evt"
	"github.com/0xERR0R/blocky/lists/parsers"
	"github.com/0xERR0R/blocky/log"
	"github.com/0xERR0R/blocky/util"
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
	)
	BeforeEach(func() {
		tmpDir = NewTmpFolder("ListCache")
		Expect(tmpDir.Error).Should(Succeed())
		DeferCleanup(tmpDir.Clean)

		server1 = TestServer("blocked1.com\nblocked1a.com\n192.168.178.55")
		DeferCleanup(server1.Close)
		server2 = TestServer("blocked2.com")
		DeferCleanup(server2.Close)
		server3 = TestServer("blocked3.com\nblocked1a.com")
		DeferCleanup(server3.Close)

		emptyFile = tmpDir.CreateStringFile("empty", "#empty file")
		Expect(emptyFile.Error).Should(Succeed())
		file1 = tmpDir.CreateStringFile("file1", "blocked1.com", "blocked1a.com")
		Expect(file1.Error).Should(Succeed())
		file2 = tmpDir.CreateStringFile("file2", "blocked2.com")
		Expect(file2.Error).Should(Succeed())
		file3 = tmpDir.CreateStringFile("file3", "blocked3.com", "blocked1a.com")
		Expect(file3.Error).Should(Succeed())
	})

	Describe("List cache and matching", func() {
		When("Query with empty", func() {
			It("should not panic", func() {
				lists := map[string][]string{
					"gr0": {emptyFile.Path},
				}
				sut, err := NewListCache(ListCacheTypeBlacklist, lists, 0, NewDownloader(), defaultProcessingConcurrency, false)
				Expect(err).Should(Succeed())

				group := sut.Match("", []string{"gr0"})
				Expect(group).Should(BeEmpty())
			})
		})

		When("List is empty", func() {
			It("should not match anything", func() {
				lists := map[string][]string{
					"gr1": {emptyFile.Path},
				}
				sut, err := NewListCache(ListCacheTypeBlacklist, lists, 0, NewDownloader(), defaultProcessingConcurrency, false)
				Expect(err).Should(Succeed())

				group := sut.Match("google.com", []string{"gr1"})
				Expect(group).Should(BeEmpty())
			})
		})
		When("List becomes empty on refresh", func() {
			It("should delete existing elements from group cache", func() {
				mockDownloader := newMockDownloader(func(res chan<- string, err chan<- error) {
					res <- "blocked1.com"
					res <- "# nothing"
				})

				lists := map[string][]string{
					"gr1": {mockDownloader.ListSource()},
				}

				sut, err := NewListCache(
					ListCacheTypeBlacklist, lists,
					4*time.Hour,
					mockDownloader,
					defaultProcessingConcurrency,
					false,
				)
				Expect(err).Should(Succeed())

				group := sut.Match("blocked1.com", []string{"gr1"})
				Expect(group).Should(ContainElement("gr1"))

				err = sut.refresh(false)
				Expect(err).Should(Succeed())

				group = sut.Match("blocked1.com", []string{"gr1"})
				Expect(group).Should(BeEmpty())
			})
		})
		When("List has invalid lines", func() {
			It("should still other domains", func() {
				lists := map[string][]string{
					"gr1": {
						inlineList(
							"inlinedomain1.com",
							"invaliddomain!",
							"inlinedomain2.com",
						),
					},
				}

				sut, err := NewListCache(ListCacheTypeBlacklist, lists, 0, NewDownloader(),
					defaultProcessingConcurrency, false)
				Expect(err).Should(Succeed())

				group := sut.Match("inlinedomain1.com", []string{"gr1"})
				Expect(group).Should(ContainElement("gr1"))

				group = sut.Match("inlinedomain2.com", []string{"gr1"})
				Expect(group).Should(ContainElement("gr1"))
			})
		})
		When("a temporary/transient err occurs on download", func() {
			It("should not delete existing elements from group cache", func() {
				// should produce a transient error on second and third attempt
				mockDownloader := newMockDownloader(func(res chan<- string, err chan<- error) {
					res <- "blocked1.com"
					err <- &TransientError{inner: errors.New("boom")}
					err <- &TransientError{inner: errors.New("boom")}
				})

				lists := map[string][]string{
					"gr1": {mockDownloader.ListSource()},
				}

				sut, err := NewListCache(
					ListCacheTypeBlacklist, lists,
					4*time.Hour,
					mockDownloader,
					defaultProcessingConcurrency,
					false,
				)
				Expect(err).Should(Succeed())

				By("Lists loaded without timeout", func() {
					Eventually(func(g Gomega) {
						group := sut.Match("blocked1.com", []string{"gr1"})
						g.Expect(group).Should(ContainElement("gr1"))
					}, "1s").Should(Succeed())
				})

				Expect(sut.refresh(false)).Should(HaveOccurred())

				By("List couldn't be loaded due to timeout", func() {
					group := sut.Match("blocked1.com", []string{"gr1"})
					Expect(group).Should(ContainElement("gr1"))
				})

				sut.Refresh()

				By("List couldn't be loaded due to timeout", func() {
					group := sut.Match("blocked1.com", []string{"gr1"})
					Expect(group).Should(ContainElement("gr1"))
				})
			})
		})
		When("non transient err occurs on download", func() {
			It("should keep existing elements from group cache", func() {
				// should produce a non transient error on second attempt
				mockDownloader := newMockDownloader(func(res chan<- string, err chan<- error) {
					res <- "blocked1.com"
					err <- errors.New("boom")
				})

				lists := map[string][]string{
					"gr1": {mockDownloader.ListSource()},
				}

				sut, err := NewListCache(ListCacheTypeBlacklist, lists, 0, mockDownloader,
					defaultProcessingConcurrency, false)
				Expect(err).Should(Succeed())

				By("Lists loaded without err", func() {
					group := sut.Match("blocked1.com", []string{"gr1"})
					Expect(group).Should(ContainElement("gr1"))
				})

				Expect(sut.refresh(false)).Should(HaveOccurred())

				By("Lists from first load is kept", func() {
					group := sut.Match("blocked1.com", []string{"gr1"})
					Expect(group).Should(ContainElement("gr1"))
				})
			})
		})
		When("Configuration has 3 external working urls", func() {
			It("should download the list and match against", func() {
				lists := map[string][]string{
					"gr1": {server1.URL, server2.URL},
					"gr2": {server3.URL},
				}

				sut, _ := NewListCache(ListCacheTypeBlacklist, lists, 0, NewDownloader(), defaultProcessingConcurrency, false)

				group := sut.Match("blocked1.com", []string{"gr1", "gr2"})
				Expect(group).Should(ContainElement("gr1"))

				group = sut.Match("blocked1a.com", []string{"gr1", "gr2"})
				Expect(group).Should(ContainElement("gr1"))

				group = sut.Match("blocked1a.com", []string{"gr2"})
				Expect(group).Should(ContainElement("gr2"))
			})
		})
		When("Configuration has some faulty urls", func() {
			It("should download the list and match against", func() {
				lists := map[string][]string{
					"gr1": {server1.URL, server2.URL, "doesnotexist"},
					"gr2": {server3.URL, "someotherfile"},
				}

				sut, _ := NewListCache(ListCacheTypeBlacklist, lists, 0, NewDownloader(), defaultProcessingConcurrency, false)

				group := sut.Match("blocked1.com", []string{"gr1", "gr2"})
				Expect(group).Should(ContainElement("gr1"))

				group = sut.Match("blocked1a.com", []string{"gr1", "gr2"})
				Expect(group).Should(ContainElements("gr1", "gr2"))

				group = sut.Match("blocked1a.com", []string{"gr2"})
				Expect(group).Should(ContainElement("gr2"))
			})
		})
		When("List will be updated", func() {
			It("event should be fired and contain count of elements in downloaded lists", func() {
				lists := map[string][]string{
					"gr1": {server1.URL},
				}

				resultCnt := 0

				_ = Bus().SubscribeOnce(BlockingCacheGroupChanged, func(listType ListCacheType, group string, cnt int) {
					resultCnt = cnt
				})

				sut, err := NewListCache(ListCacheTypeBlacklist, lists, 0, NewDownloader(), defaultProcessingConcurrency, false)
				Expect(err).Should(Succeed())

				group := sut.Match("blocked1.com", []string{})
				Expect(group).Should(BeEmpty())
				Expect(resultCnt).Should(Equal(3))
			})
		})
		When("multiple groups are passed", func() {
			It("should match", func() {
				lists := map[string][]string{
					"gr1": {file1.Path, file2.Path},
					"gr2": {"file://" + file3.Path},
				}

				sut, err := NewListCache(ListCacheTypeBlacklist, lists, 0, NewDownloader(), defaultProcessingConcurrency, false)
				Expect(err).Should(Succeed())

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
			It("should match", func() {
				file1, lines1 := createTestListFile(GinkgoT().TempDir(), 10000)
				file2, lines2 := createTestListFile(GinkgoT().TempDir(), 15000)
				file3, lines3 := createTestListFile(GinkgoT().TempDir(), 13000)
				lists := map[string][]string{
					"gr1": {file1, file2, file3},
				}

				sut, err := NewListCache(ListCacheTypeBlacklist, lists, 0, NewDownloader(),
					defaultProcessingConcurrency, false)
				Expect(err).Should(Succeed())

				Expect(sut.groupedCache.ElementCount("gr1")).Should(Equal(lines1 + lines2 + lines3))
			})
		})
		When("inline list content is defined", func() {
			It("should match", func() {
				lists := map[string][]string{
					"gr1": {inlineList(
						"inlinedomain1.com",
						"#some comment",
						"inlinedomain2.com",
					)},
				}

				sut, err := NewListCache(ListCacheTypeBlacklist, lists, 0, NewDownloader(),
					defaultProcessingConcurrency, false)
				Expect(err).Should(Succeed())

				Expect(sut.groupedCache.ElementCount("gr1")).Should(Equal(2))
				group := sut.Match("inlinedomain1.com", []string{"gr1"})
				Expect(group).Should(ContainElement("gr1"))

				group = sut.Match("inlinedomain2.com", []string{"gr1"})
				Expect(group).Should(ContainElement("gr1"))
			})
		})
		When("Text file can't be parsed", func() {
			It("should still match already imported strings", func() {
				lists := map[string][]string{
					"gr1": {
						inlineList(
							"inlinedomain1.com",
							"lineTooLong"+strings.Repeat("x", bufio.MaxScanTokenSize), // too long
						),
					},
				}

				sut, err := NewListCache(ListCacheTypeBlacklist, lists, 0, NewDownloader(),
					defaultProcessingConcurrency, false)
				Expect(err).Should(Succeed())

				group := sut.Match("inlinedomain1.com", []string{"gr1"})
				Expect(group).Should(ContainElement("gr1"))
			})
		})
		When("Text file has too many errors", func() {
			It("should fail parsing", func() {
				lists := map[string][]string{
					"gr1": {
						inlineList(
							strings.Repeat("invaliddomain!\n", maxErrorsPerFile+1), // too many errors
						),
					},
				}

				_, err := NewListCache(ListCacheTypeBlacklist, lists, 0, NewDownloader(),
					defaultProcessingConcurrency, false)
				Expect(err).ShouldNot(Succeed())
				Expect(err).Should(MatchError(parsers.ErrTooManyErrors))
			})
		})
		When("file has end of line comment", func() {
			It("should still parse the domain", func() {
				lists := map[string][]string{
					"gr1": {inlineList("inlinedomain1.com#a comment")},
				}

				sut, err := NewListCache(ListCacheTypeBlacklist, lists, 0, NewDownloader(),
					defaultProcessingConcurrency, false)
				Expect(err).Should(Succeed())

				group := sut.Match("inlinedomain1.com", []string{"gr1"})
				Expect(group).Should(ContainElement("gr1"))
			})
		})
		When("inline regex content is defined", func() {
			It("should match", func() {
				lists := map[string][]string{
					"gr1": {inlineList("/^apple\\.(de|com)$/")},
				}

				sut, err := NewListCache(ListCacheTypeBlacklist, lists, 0, NewDownloader(),
					defaultProcessingConcurrency, false)
				Expect(err).Should(Succeed())

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
		})

		It("should print list configuration", func() {
			lists := map[string][]string{
				"gr1": {server1.URL, server2.URL},
				"gr2": {inlineList("inline", "definition")},
			}

			sut, err := NewListCache(ListCacheTypeBlacklist, lists, time.Hour, NewDownloader(),
				defaultProcessingConcurrency, false)
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
			It("should never return an error", func() {
				lists := map[string][]string{
					"gr1": {"doesnotexist"},
				}

				_, err := NewListCache(ListCacheTypeBlacklist, lists, -1, NewDownloader(),
					defaultProcessingConcurrency, true)
				Expect(err).Should(Succeed())
			})
		})
	})
})

type MockDownloader struct {
	util.MockCallSequence[string]
}

func newMockDownloader(driver func(res chan<- string, err chan<- error)) *MockDownloader {
	return &MockDownloader{util.NewMockCallSequence(driver)}
}

func (m *MockDownloader) DownloadFile(_ string) (io.ReadCloser, error) {
	str, err := m.Call()
	if err != nil {
		return nil, err
	}

	return io.NopCloser(strings.NewReader(str)), nil
}

func (m *MockDownloader) ListSource() string {
	return "http://mock"
}

func createTestListFile(dir string, totalLines int) (string, int) {
	file, err := os.CreateTemp(dir, "blocky")
	if err != nil {
		log.Log().Fatal(err)
	}

	w := bufio.NewWriter(file)
	for i := 0; i < totalLines; i++ {
		fmt.Fprintln(w, RandStringBytes(8+rand.Intn(10))+".com")
	}
	w.Flush()

	return file.Name(), totalLines
}

const (
	initCharpool = "abcdefghijklmnopqrstuvwxyz"
	contCharpool = initCharpool + "0123456789-"
)

func RandStringBytes(n int) string {
	b := make([]byte, n)

	pool := initCharpool

	for i := range b {
		b[i] = pool[rand.Intn(len(pool))]

		pool = contCharpool
	}

	return string(b)
}

func inlineList(lines ...string) string {
	res := strings.Join(lines, "\n")

	// ensure at least one line ending so it's parsed as an inline block
	res += "\n"

	return res
}
