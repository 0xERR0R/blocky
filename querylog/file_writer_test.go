package querylog

import (
	"bufio"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/0xERR0R/blocky/helpertest"
	"github.com/0xERR0R/blocky/log"

	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"
	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("FileWriter", func() {
	var (
		tmpDir *helpertest.TmpFolder
		err    error
		writer *FileWriter
	)

	JustBeforeEach(func() {
		tmpDir = helpertest.NewTmpFolder("fileWriter")
		Expect(tmpDir.Error).Should(Succeed())
		DeferCleanup(tmpDir.Clean)
	})

	Describe("CSV writer", func() {
		When("target dir does not exist", func() {
			It("should return error", func() {
				_, err = NewCSVWriter("wrongdir", false, 0)
				Expect(err).Should(HaveOccurred())
			})
		})
		When("New log entry was created", func() {
			It("should be logged in one file", func() {
				writer, err = NewCSVWriter(tmpDir.Path, false, 0)

				Expect(err).Should(Succeed())

				res, err := util.NewMsgWithAnswer("example.com", 123, dns.Type(dns.TypeA), "123.124.122.122")

				Expect(err).Should(Succeed())

				By("entry for client 1", func() {
					writer.Write(&LogEntry{
						Request: &model.Request{
							ClientNames: []string{"client1"},
							Req:         util.NewMsgWithQuestion("google.de.", dns.Type(dns.TypeA)),
							RequestTS:   time.Time{},
						},
						Response: &model.Response{
							Res:    res,
							Reason: "Resolved",
							RType:  model.ResponseTypeRESOLVED,
						},
						Start:      time.Now(),
						DurationMs: 20,
					})
				})

				By("entry for client 2", func() {
					writer.Write(&LogEntry{
						Request: &model.Request{
							ClientNames: []string{"client2"},
							Req:         util.NewMsgWithQuestion("google.de.", dns.Type(dns.TypeA)),
							RequestTS:   time.Time{},
						},
						Response: &model.Response{
							Res:    res,
							Reason: "Resolved",
							RType:  model.ResponseTypeRESOLVED,
						},
						Start:      time.Now(),
						DurationMs: 20,
					})
				})

				Eventually(func(g Gomega) int {
					return len(readCsv(tmpDir.JoinPath(
						fmt.Sprintf("%s_ALL.log", time.Now().Format("2006-01-02")))))
				}).Should(Equal(2))
			})

			It("should be logged in separate files per client", func() {
				writer, err = NewCSVWriter(tmpDir.Path, true, 0)

				Expect(err).Should(Succeed())

				res, err := util.NewMsgWithAnswer("example.com", 123, dns.Type(dns.TypeA), "123.124.122.122")

				Expect(err).Should(Succeed())

				By("entry for client 1", func() {
					writer.Write(&LogEntry{
						Request: &model.Request{
							ClientNames: []string{"client1"},
							Req:         util.NewMsgWithQuestion("google.de.", dns.Type(dns.TypeA)),
							RequestTS:   time.Time{},
						},
						Response: &model.Response{
							Res:    res,
							Reason: "Resolved",
							RType:  model.ResponseTypeRESOLVED,
						},
						Start:      time.Now(),
						DurationMs: 20,
					})
				})

				By("entry for client 2", func() {
					writer.Write(&LogEntry{
						Request: &model.Request{
							ClientNames: []string{"client2"},
							Req:         util.NewMsgWithQuestion("google.de.", dns.Type(dns.TypeA)),
							RequestTS:   time.Time{},
						},
						Response: &model.Response{
							Res:    res,
							Reason: "Resolved",
							RType:  model.ResponseTypeRESOLVED,
						},
						Start:      time.Now(),
						DurationMs: 20,
					})
				})

				Eventually(func(g Gomega) int {
					return len(readCsv(tmpDir.JoinPath(
						fmt.Sprintf("%s_client1.log", time.Now().Format("2006-01-02")))))
				}).Should(Equal(1))

				Eventually(func(g Gomega) int {
					return len(readCsv(tmpDir.JoinPath(
						fmt.Sprintf("%s_client2.log", time.Now().Format("2006-01-02")))))
				}).Should(Equal(1))

			})
		})
		When("Cleanup is called", func() {
			It("should delete old files", func() {
				writer, err = NewCSVWriter(tmpDir.Path, false, 1)

				Expect(err).Should(Succeed())

				res, err := util.NewMsgWithAnswer("example.com", 123, dns.Type(dns.TypeA), "123.124.122.122")

				Expect(err).Should(Succeed())

				By("entry today", func() {
					writer.Write(&LogEntry{
						Request: &model.Request{
							ClientNames: []string{"client1"},
							Req:         util.NewMsgWithQuestion("google.de.", dns.Type(dns.TypeA)),
							RequestTS:   time.Now(),
						},
						Response: &model.Response{
							Res:    res,
							Reason: "Resolved",
							RType:  model.ResponseTypeRESOLVED,
						},
						Start:      time.Now(),
						DurationMs: 20,
					})
				})
				By("entry 2 days ago", func() {
					writer.Write(&LogEntry{
						Request: &model.Request{
							ClientNames: []string{"client1"},
							Req:         util.NewMsgWithQuestion("google.de.", dns.Type(dns.TypeA)),
							RequestTS:   time.Now(),
						},
						Response: &model.Response{
							Res:    res,
							Reason: "Resolved",
							RType:  model.ResponseTypeRESOLVED,
						},
						Start:      time.Now().AddDate(0, 0, -3),
						DurationMs: 20,
					})
				})
				fmt.Println(tmpDir.Path)

				Eventually(func(g Gomega) int {
					filesCount, err := tmpDir.CountFiles()
					g.Expect(err).Should(Succeed())

					return filesCount
				}, "20s", "1s").Should(Equal(2))

				go writer.CleanUp()

				Eventually(func(g Gomega) int {
					filesCount, err := tmpDir.CountFiles()
					g.Expect(err).Should(Succeed())

					return filesCount
				}, "20s", "1s").Should(Equal(1))
			})
		})
	})

})

func readCsv(file string) [][]string {
	var result [][]string

	csvFile, err := os.Open(file)
	Expect(err).Should(Succeed())

	reader := csv.NewReader(bufio.NewReader(csvFile))
	reader.Comma = '\t'

	for {
		line, err := reader.Read()
		if errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			log.Log().Fatal("can't read line", err)
		}

		result = append(result, line)
	}

	return result
}
