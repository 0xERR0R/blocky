package querylog

import (
	"bufio"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/0xERR0R/blocky/log"

	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"
	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("FileWriter", func() {
	var tmpDir string
	var err error
	BeforeEach(func() {
		tmpDir, err = ioutil.TempDir("", "fileWriter")
		Expect(err).Should(Succeed())
	})
	AfterEach(func() {
		_ = os.RemoveAll(tmpDir)
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
				tmpDir, err = ioutil.TempDir("", "queryLoggingResolver")
				Expect(err).Should(Succeed())
				writer, _ := NewCSVWriter(tmpDir, false, 0)
				res, err := util.NewMsgWithAnswer("example.com", 123, dns.TypeA, "123.124.122.122")

				Expect(err).Should(Succeed())

				By("entry for client 1", func() {
					writer.Write(&Entry{
						Request: &model.Request{
							ClientNames: []string{"client1"},
							Req:         util.NewMsgWithQuestion("google.de.", dns.TypeA),
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
					writer.Write(&Entry{
						Request: &model.Request{
							ClientNames: []string{"client2"},
							Req:         util.NewMsgWithQuestion("google.de.", dns.TypeA),
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

				csvLines := readCsv(filepath.Join(tmpDir, fmt.Sprintf("%s_ALL.log", time.Now().Format("2006-01-02"))))
				Expect(csvLines).Should(HaveLen(2))

			})

			It("should be logged in separate files per client", func() {
				tmpDir, err = ioutil.TempDir("", "queryLoggingResolver")
				Expect(err).Should(Succeed())
				writer, _ := NewCSVWriter(tmpDir, true, 0)
				res, err := util.NewMsgWithAnswer("example.com", 123, dns.TypeA, "123.124.122.122")

				Expect(err).Should(Succeed())

				By("entry for client 1", func() {
					writer.Write(&Entry{
						Request: &model.Request{
							ClientNames: []string{"client1"},
							Req:         util.NewMsgWithQuestion("google.de.", dns.TypeA),
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
					writer.Write(&Entry{
						Request: &model.Request{
							ClientNames: []string{"client2"},
							Req:         util.NewMsgWithQuestion("google.de.", dns.TypeA),
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

				csvLines := readCsv(filepath.Join(tmpDir, fmt.Sprintf("%s_client1.log", time.Now().Format("2006-01-02"))))
				Expect(csvLines).Should(HaveLen(1))

				csvLines = readCsv(filepath.Join(tmpDir, fmt.Sprintf("%s_client2.log", time.Now().Format("2006-01-02"))))
				Expect(csvLines).Should(HaveLen(1))

			})
		})
		When("Cleanup is called", func() {
			It("should delete old files", func() {
				tmpDir, err = ioutil.TempDir("", "queryLoggingResolver")
				Expect(err).Should(Succeed())
				writer, _ := NewCSVWriter(tmpDir, false, 1)
				res, err := util.NewMsgWithAnswer("example.com", 123, dns.TypeA, "123.124.122.122")

				Expect(err).Should(Succeed())

				By("entry today", func() {
					writer.Write(&Entry{
						Request: &model.Request{
							ClientNames: []string{"client1"},
							Req:         util.NewMsgWithQuestion("google.de.", dns.TypeA),
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
					writer.Write(&Entry{
						Request: &model.Request{
							ClientNames: []string{"client1"},
							Req:         util.NewMsgWithQuestion("google.de.", dns.TypeA),
							RequestTS:   time.Now(),
						},
						Response: &model.Response{
							Res:    res,
							Reason: "Resolved",
							RType:  model.ResponseTypeRESOLVED,
						},
						Start:      time.Now().AddDate(0, 0, -2),
						DurationMs: 20,
					})
				})

				files, err := ioutil.ReadDir(tmpDir)
				Expect(err).Should(Succeed())
				Expect(files).Should(HaveLen(2))
				writer.CleanUp()

				files, err = ioutil.ReadDir(tmpDir)
				Expect(err).Should(Succeed())
				Expect(files).Should(HaveLen(1))
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
