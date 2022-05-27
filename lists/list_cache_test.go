package lists

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http/httptest"
	"os"
	"strings"
	"time"

	. "github.com/0xERR0R/blocky/evt"

	. "github.com/0xERR0R/blocky/helpertest"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("ListCache", func() {
	var (
		emptyFile, file1, file2, file3 *os.File
		server1, server2, server3      *httptest.Server
	)
	BeforeEach(func() {
		emptyFile = TempFile("#empty file\n\n")
		server1 = TestServer("blocked1.com\nblocked1a.com\n192.168.178.55")
		server2 = TestServer("blocked2.com")
		server3 = TestServer("blocked3.com\nblocked1a.com")

		file1 = TempFile("blocked1.com\nblocked1a.com")
		file2 = TempFile("blocked2.com")
		file3 = TempFile("blocked3.com\nblocked1a.com")
	})
	AfterEach(func() {
		_ = os.Remove(emptyFile.Name())
		_ = os.Remove(file1.Name())
		_ = os.Remove(file2.Name())
		_ = os.Remove(file3.Name())
		server1.Close()
		server2.Close()
		server3.Close()
	})

	Describe("List cache and matching", func() {
		When("Query with empty", func() {
			It("should not panic", func() {
				lists := map[string][]string{
					"gr0": {emptyFile.Name()},
				}
				sut, err := NewListCache(ListCacheTypeBlacklist, lists, 0, NewDownloader(), defaultProcessingConcurrency)
				Expect(err).Should(Succeed())

				found, group := sut.Match("", []string{"gr0"})
				Expect(found).Should(BeFalse())
				Expect(group).Should(BeEmpty())
			})
		})

		When("List is empty", func() {
			It("should not match anything", func() {
				lists := map[string][]string{
					"gr1": {emptyFile.Name()},
				}
				sut, err := NewListCache(ListCacheTypeBlacklist, lists, 0, NewDownloader(), defaultProcessingConcurrency)
				Expect(err).Should(Succeed())

				found, group := sut.Match("google.com", []string{"gr1"})
				Expect(found).Should(BeFalse())
				Expect(group).Should(BeEmpty())

			})
		})
		When("a temporary/transient err occurs on download", func() {
			It("should not delete existing elements from group cache", func() {
				// should produce a transient error on second and third attempt
				data := make(chan func() (io.ReadCloser, error), 3)
				mockDownloader := &MockDownloader{data: data}
				data <- func() (io.ReadCloser, error) {
					return io.NopCloser(strings.NewReader("blocked1.com")), nil
				}
				data <- func() (io.ReadCloser, error) {
					return nil, &TransientError{inner: errors.New("boom")}
				}
				data <- func() (io.ReadCloser, error) {
					return nil, &TransientError{inner: errors.New("boom")}
				}
				lists := map[string][]string{
					"gr1": {"http://dummy"},
				}

				sut, err := NewListCache(
					ListCacheTypeBlacklist, lists,
					4*time.Hour,
					mockDownloader,
					defaultProcessingConcurrency,
				)
				Expect(err).Should(Succeed())

				By("Lists loaded without timeout", func() {
					Eventually(func(g Gomega) {
						found, group := sut.Match("blocked1.com", []string{"gr1"})
						g.Expect(found).Should(BeTrue())
						g.Expect(group).Should(Equal("gr1"))
					}, "1s").Should(Succeed())

				})

				Expect(sut.refresh(true)).Should(HaveOccurred())

				By("List couldn't be loaded due to timeout", func() {
					found, group := sut.Match("blocked1.com", []string{"gr1"})
					Expect(found).Should(BeTrue())
					Expect(group).Should(Equal("gr1"))
				})

				sut.Refresh()

				By("List couldn't be loaded due to timeout", func() {
					found, group := sut.Match("blocked1.com", []string{"gr1"})
					Expect(found).Should(BeTrue())
					Expect(group).Should(Equal("gr1"))
				})
			})
		})
		When("non transient err occurs on download", func() {
			It("should delete existing elements from group cache", func() {
				// should produce a 404 err on second attempt
				data := make(chan func() (io.ReadCloser, error), 2)
				mockDownloader := &MockDownloader{data: data}
				data <- func() (io.ReadCloser, error) {
					return io.NopCloser(strings.NewReader("blocked1.com")), nil
				}
				data <- func() (io.ReadCloser, error) {
					return nil, errors.New("boom")
				}
				lists := map[string][]string{
					"gr1": {"http://dummy"},
				}

				sut, err := NewListCache(ListCacheTypeBlacklist, lists, 0, mockDownloader, defaultProcessingConcurrency)
				Expect(err).Should(Succeed())

				By("Lists loaded without err", func() {
					Eventually(func(g Gomega) {
						found, group := sut.Match("blocked1.com", []string{"gr1"})
						g.Expect(found).Should(BeTrue())
						g.Expect(group).Should(Equal("gr1"))
					}, "1s").Should(Succeed())

				})

				Expect(sut.refresh(false)).Should(HaveOccurred())

				By("List couldn't be loaded due to 404 err", func() {
					Eventually(func() bool {
						found, _ := sut.Match("blocked1.com", []string{"gr1"})

						return found
					}, "1s").Should(BeFalse())
				})
			})
		})
		When("Configuration has 3 external working urls", func() {
			It("should download the list and match against", func() {
				lists := map[string][]string{
					"gr1": {server1.URL, server2.URL},
					"gr2": {server3.URL},
				}

				sut, _ := NewListCache(ListCacheTypeBlacklist, lists, 0, NewDownloader(), defaultProcessingConcurrency)

				found, group := sut.Match("blocked1.com", []string{"gr1", "gr2"})
				Expect(found).Should(BeTrue())
				Expect(group).Should(Equal("gr1"))

				found, group = sut.Match("blocked1a.com", []string{"gr1", "gr2"})
				Expect(found).Should(BeTrue())
				Expect(group).Should(Equal("gr1"))

				found, group = sut.Match("blocked1a.com", []string{"gr2"})
				Expect(found).Should(BeTrue())
				Expect(group).Should(Equal("gr2"))
			})
		})
		When("Configuration has some faulty urls", func() {
			It("should download the list and match against", func() {
				lists := map[string][]string{
					"gr1": {server1.URL, server2.URL, "doesnotexist"},
					"gr2": {server3.URL, "someotherfile"},
				}

				sut, _ := NewListCache(ListCacheTypeBlacklist, lists, 0, NewDownloader(), defaultProcessingConcurrency)

				found, group := sut.Match("blocked1.com", []string{"gr1", "gr2"})
				Expect(found).Should(BeTrue())
				Expect(group).Should(Equal("gr1"))

				found, group = sut.Match("blocked1a.com", []string{"gr1", "gr2"})
				Expect(found).Should(BeTrue())
				Expect(group).Should(Equal("gr1"))

				found, group = sut.Match("blocked1a.com", []string{"gr2"})
				Expect(found).Should(BeTrue())
				Expect(group).Should(Equal("gr2"))
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

				sut, err := NewListCache(ListCacheTypeBlacklist, lists, 0, NewDownloader(), defaultProcessingConcurrency)
				Expect(err).Should(Succeed())

				found, group := sut.Match("blocked1.com", []string{})
				Expect(found).Should(BeFalse())
				Expect(group).Should(BeEmpty())
				Expect(resultCnt).Should(Equal(3))
			})
		})
		When("multiple groups are passed", func() {
			It("should match", func() {
				lists := map[string][]string{
					"gr1": {file1.Name(), file2.Name()},
					"gr2": {"file://" + file3.Name()},
				}

				sut, err := NewListCache(ListCacheTypeBlacklist, lists, 0, NewDownloader(), defaultProcessingConcurrency)
				Expect(err).Should(Succeed())

				Expect(sut.groupCaches["gr1"].ElementCount()).Should(Equal(3))
				Expect(sut.groupCaches["gr2"].ElementCount()).Should(Equal(2))

				found, group := sut.Match("blocked1.com", []string{"gr1", "gr2"})
				Expect(found).Should(BeTrue())
				Expect(group).Should(Equal("gr1"))

				found, group = sut.Match("blocked1a.com", []string{"gr1", "gr2"})
				Expect(found).Should(BeTrue())
				Expect(group).Should(Equal("gr1"))

				found, group = sut.Match("blocked1a.com", []string{"gr2"})
				Expect(found).Should(BeTrue())
				Expect(group).Should(Equal("gr2"))
			})
		})
		When("group with bigger files", func() {
			It("should match", func() {
				file1 := createTestListFile(GinkgoT().TempDir(), 10000)
				file2 := createTestListFile(GinkgoT().TempDir(), 15000)
				file3 := createTestListFile(GinkgoT().TempDir(), 13000)
				lists := map[string][]string{
					"gr1": {file1, file2, file3},
				}

				sut, err := NewListCache(ListCacheTypeBlacklist, lists, 0, NewDownloader(), defaultProcessingConcurrency)
				Expect(err).Should(Succeed())

				Expect(sut.groupCaches["gr1"].ElementCount()).Should(Equal(38000))
			})
		})
		When("inline list content is defined", func() {
			It("should match", func() {
				lists := map[string][]string{
					"gr1": {"inlinedomain1.com\n#some comment\ninlinedomain2.com"},
				}

				sut, err := NewListCache(ListCacheTypeBlacklist, lists, 0, NewDownloader(), defaultProcessingConcurrency)
				Expect(err).Should(Succeed())

				Expect(sut.groupCaches["gr1"].ElementCount()).Should(Equal(2))
				found, group := sut.Match("inlinedomain1.com", []string{"gr1"})
				Expect(found).Should(BeTrue())
				Expect(group).Should(Equal("gr1"))

				found, group = sut.Match("inlinedomain2.com", []string{"gr1"})
				Expect(found).Should(BeTrue())
				Expect(group).Should(Equal("gr1"))
			})
		})
		When("Text file can't be parsed", func() {
			It("should still match already imported strings", func() {
				// 2nd line is too long and will cause an error
				lists := map[string][]string{
					"gr1": {"inlinedomain1.com\n" + strings.Repeat("longString", 100000)},
				}

				sut, err := NewListCache(ListCacheTypeBlacklist, lists, 0, NewDownloader(), defaultProcessingConcurrency)
				Expect(err).Should(Succeed())

				found, group := sut.Match("inlinedomain1.com", []string{"gr1"})
				Expect(found).Should(BeTrue())
				Expect(group).Should(Equal("gr1"))
			})
		})
		When("inline regex content is defined", func() {
			It("should match", func() {
				lists := map[string][]string{
					"gr1": {"/^apple\\.(de|com)$/\n"},
				}

				sut, err := NewListCache(ListCacheTypeBlacklist, lists, 0, NewDownloader(), defaultProcessingConcurrency)
				Expect(err).Should(Succeed())

				found, group := sut.Match("apple.com", []string{"gr1"})
				Expect(found).Should(BeTrue())
				Expect(group).Should(Equal("gr1"))

				found, group = sut.Match("apple.de", []string{"gr1"})
				Expect(found).Should(BeTrue())
				Expect(group).Should(Equal("gr1"))
			})
		})
	})
	Describe("Configuration", func() {
		When("refresh is enabled", func() {
			It("should print list configuration", func() {
				lists := map[string][]string{
					"gr1": {server1.URL, server2.URL},
					"gr2": {"inline\ndefinition\n"},
				}

				sut, err := NewListCache(ListCacheTypeBlacklist, lists, time.Hour, NewDownloader(), defaultProcessingConcurrency)
				Expect(err).Should(Succeed())

				c := sut.Configuration()
				Expect(c).Should(ContainElement("refresh period: 1 hour"))
				Expect(c).Should(HaveLen(11))
			})
		})
		When("refresh is disabled", func() {
			It("should print 'refresh disabled'", func() {
				lists := map[string][]string{
					"gr1": {emptyFile.Name()},
				}

				sut, err := NewListCache(ListCacheTypeBlacklist, lists, -1, NewDownloader(), defaultProcessingConcurrency)
				Expect(err).Should(Succeed())

				c := sut.Configuration()
				Expect(c).Should(ContainElement("refresh: disabled"))
			})
		})
	})
})

type MockDownloader struct {
	data chan func() (io.ReadCloser, error)
}

func (m *MockDownloader) DownloadFile(_ string) (io.ReadCloser, error) {
	fn := <-m.data

	return fn()
}

func createTestListFile(dir string, totalLines int) string {
	file, err := ioutil.TempFile(dir, "blocky")
	if err != nil {
		log.Fatal(err)
	}

	w := bufio.NewWriter(file)
	for i := 0; i < totalLines; i++ {
		fmt.Fprintln(w, RandStringBytes(8+rand.Intn(10))+".com") // nolint:gosec
	}
	w.Flush()

	return file.Name()
}

const charpool = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-"

func RandStringBytes(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = charpool[rand.Intn(len(charpool))] // nolint:gosec
	}

	return string(b)
}
