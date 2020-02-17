package resolver

import (
	"blocky/config"
	"blocky/util"
	"bufio"
	"encoding/csv"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func Test_New_LogDirNotExist(t *testing.T) {
	defer func() { logrus.StandardLogger().ExitFunc = nil }()

	var fatal bool

	logrus.StandardLogger().ExitFunc = func(int) { fatal = true }
	_ = NewQueryLoggingResolver(config.QueryLogConfig{Dir: "notExists"})

	assert.True(t, fatal)
}

func Test_doCleanUp_WrongDir(t *testing.T) {
	defer func() { logrus.StandardLogger().ExitFunc = nil }()

	var fatal bool

	logrus.StandardLogger().ExitFunc = func(int) { fatal = true }

	sut := NewQueryLoggingResolver(config.QueryLogConfig{
		Dir:              "wrongDir",
		LogRetentionDays: 7,
	})

	sut.(*QueryLoggingResolver).doCleanUp()
	assert.True(t, fatal)
}

func Test_doCleanUp(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "queryLoggingResolver")
	defer os.RemoveAll(tmpDir)
	assert.NoError(t, err)

	// create 2 files, 7 and 8 days old
	dateBefore7Days := time.Now().AddDate(0, 0, -7)
	dateBefore8Days := time.Now().AddDate(0, 0, -8)

	f1, err := os.Create(filepath.Join(tmpDir, fmt.Sprintf("%s-test.log", dateBefore7Days.Format("2006-01-02"))))
	assert.NoError(t, err)

	f2, err := os.Create(filepath.Join(tmpDir, fmt.Sprintf("%s-test.log", dateBefore8Days.Format("2006-01-02"))))
	assert.NoError(t, err)

	sut := NewQueryLoggingResolver(config.QueryLogConfig{
		Dir:              tmpDir,
		LogRetentionDays: 7,
	})

	sut.(*QueryLoggingResolver).doCleanUp()

	// file 1 exist
	_, err = os.Stat(f1.Name())
	assert.NoError(t, err)

	// file 2 was deleted
	_, err = os.Stat(f2.Name())
	assert.Error(t, err)
	assert.True(t, os.IsNotExist(err))
}

func Test_Resolve_WithEmptyConfig(t *testing.T) {
	sut := NewQueryLoggingResolver(config.QueryLogConfig{})
	m := &resolverMock{}
	resp, err := util.NewMsgWithAnswer("example.com. 300 IN A 123.122.121.120")
	assert.NoError(t, err)

	m.On("Resolve", mock.Anything).Return(&Response{Res: resp, Reason: "reason"}, nil)
	sut.Next(m)

	_, err = sut.Resolve(&Request{
		ClientIP:    net.ParseIP("192.168.178.25"),
		ClientNames: []string{"client1"},
		Req:         util.NewMsgWithQuestion("google.de.", dns.TypeA),
		Log:         logrus.NewEntry(logrus.New())})
	assert.NoError(t, err)
	m.AssertExpectations(t)
}
func Test_Resolve_WithLoggingPerClient(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "queryLoggingResolver")
	assert.NoError(t, err)

	defer os.RemoveAll(tmpDir)

	sut := NewQueryLoggingResolver(config.QueryLogConfig{
		Dir:       tmpDir,
		PerClient: true,
	})

	m := &resolverMock{}
	resp, err := util.NewMsgWithAnswer("example.com. 300 IN A 123.122.121.120")
	assert.NoError(t, err)

	m.On("Resolve", mock.Anything).Return(&Response{Res: resp, Reason: "reason"}, nil)
	sut.Next(m)

	// request client1
	_, err = sut.Resolve(&Request{
		ClientIP:    net.ParseIP("192.168.178.25"),
		ClientNames: []string{"client1"},
		Req:         util.NewMsgWithQuestion("google.de.", dns.TypeA),
		Log:         logrus.NewEntry(logrus.New())})
	assert.NoError(t, err)

	// request client2, has name with spechial chars, should be escaped
	_, err = sut.Resolve(&Request{
		ClientIP:    net.ParseIP("192.168.178.26"),
		ClientNames: []string{"cl/ient2\\$%&test"},
		Req:         util.NewMsgWithQuestion("google.de.", dns.TypeA),
		Log:         logrus.NewEntry(logrus.New())})
	assert.NoError(t, err)

	time.Sleep(100 * time.Millisecond)

	m.AssertExpectations(t)

	// client1
	csvLines := readCsv(filepath.Join(tmpDir, fmt.Sprintf("%s_client1.log", time.Now().Format("2006-01-02"))))

	assert.Len(t, csvLines, 1)
	assert.Equal(t, "192.168.178.25", csvLines[0][1])
	assert.Equal(t, "client1", csvLines[0][2])
	assert.Equal(t, "reason", csvLines[0][4])
	assert.Equal(t, "A (google.de.)", csvLines[0][5])
	assert.Equal(t, "A (123.122.121.120)", csvLines[0][6])

	// client2
	csvLines = readCsv(filepath.Join(tmpDir, fmt.Sprintf("%s_cl_ient2_test.log", time.Now().Format("2006-01-02"))))

	assert.Len(t, csvLines, 1)
	assert.Equal(t, "192.168.178.26", csvLines[0][1])
	assert.Equal(t, "cl/ient2\\$%&test", csvLines[0][2])
	assert.Equal(t, "reason", csvLines[0][4])
	assert.Equal(t, "A (google.de.)", csvLines[0][5])
	assert.Equal(t, "A (123.122.121.120)", csvLines[0][6])
}

func Test_Resolve_WithLoggingAll(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "queryLoggingResolver")
	assert.NoError(t, err)

	defer os.RemoveAll(tmpDir)

	sut := NewQueryLoggingResolver(config.QueryLogConfig{
		Dir:       tmpDir,
		PerClient: false,
	})

	m := &resolverMock{}
	resp, err := util.NewMsgWithAnswer("example.com. 300 IN A 123.122.121.120")
	assert.NoError(t, err)

	m.On("Resolve", mock.Anything).Return(&Response{Res: resp, Reason: "reason"}, nil)
	sut.Next(m)

	// request client1
	_, err = sut.Resolve(&Request{
		ClientIP:    net.ParseIP("192.168.178.25"),
		ClientNames: []string{"client1"},
		Req:         util.NewMsgWithQuestion("google.de.", dns.TypeA),
		Log:         logrus.NewEntry(logrus.New())})
	assert.NoError(t, err)

	// request client2
	_, err = sut.Resolve(&Request{
		ClientIP:    net.ParseIP("192.168.178.26"),
		ClientNames: []string{"client2"},
		Req:         util.NewMsgWithQuestion("google.de.", dns.TypeA),
		Log:         logrus.NewEntry(logrus.New())})
	assert.NoError(t, err)

	time.Sleep(100 * time.Millisecond)

	m.AssertExpectations(t)

	csvLines := readCsv(filepath.Join(tmpDir, fmt.Sprintf("%s_ALL.log", time.Now().Format("2006-01-02"))))
	assert.Len(t, csvLines, 2)

	// client1 -> first line
	assert.Equal(t, "192.168.178.25", csvLines[0][1])
	assert.Equal(t, "client1", csvLines[0][2])
	assert.Equal(t, "reason", csvLines[0][4])
	assert.Equal(t, "A (google.de.)", csvLines[0][5])
	assert.Equal(t, "A (123.122.121.120)", csvLines[0][6])

	// client2 -> second line
	assert.Equal(t, "192.168.178.26", csvLines[1][1])
	assert.Equal(t, "client2", csvLines[1][2])
	assert.Equal(t, "reason", csvLines[1][4])
	assert.Equal(t, "A (google.de.)", csvLines[1][5])
	assert.Equal(t, "A (123.122.121.120)", csvLines[1][6])
}

func readCsv(file string) [][]string {
	var result [][]string

	csvFile, err := os.Open(file)
	if err != nil {
		log.Fatal("can't open file", err)
	}

	reader := csv.NewReader(bufio.NewReader(csvFile))
	reader.Comma = '\t'

	for {
		line, err := reader.Read()
		if err == io.EOF {
			break
		} else if err != nil {
			log.Fatal("can't read line", err)
		}

		result = append(result, line)
	}

	return result
}

func Test_Configuration_QueryLoggingResolver_WithConfig(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "queryLoggingResolver")
	assert.NoError(t, err)

	defer os.RemoveAll(tmpDir)

	sut := NewQueryLoggingResolver(config.QueryLogConfig{
		Dir:              tmpDir,
		PerClient:        true,
		LogRetentionDays: 0,
	})
	c := sut.Configuration()
	assert.Len(t, c, 4)
}

func Test_Configuration_QueryLoggingResolver_Disabled(t *testing.T) {
	sut := NewQueryLoggingResolver(config.QueryLogConfig{})
	c := sut.Configuration()
	assert.Equal(t, []string{"deactivated"}, c)
}
