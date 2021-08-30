package querylog

import (
	"strings"
	"time"

	"github.com/0xERR0R/blocky/log"

	"github.com/0xERR0R/blocky/util"
	"github.com/miekg/dns"
	"golang.org/x/net/publicsuffix"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

type logEntry struct {
	RequestTS     *time.Time `gorm:"index"`
	ClientIP      string
	ClientName    string `gorm:"index"`
	DurationMs    int64
	Reason        string
	ResponseType  string `gorm:"index"`
	QuestionType  string
	QuestionName  string
	EffectiveTLDP string
	Answer        string
	ResponseCode  string
}

type DatabaseWriter struct {
	db               *gorm.DB
	logRetentionDays int
}

func NewDatabaseWriter(target string, logRetentionDays uint64) *DatabaseWriter {
	return newDatabaseWriter(mysql.Open(target), logRetentionDays)
}

func newDatabaseWriter(target gorm.Dialector, logRetentionDays uint64) *DatabaseWriter {
	db, err := gorm.Open(target, &gorm.Config{})

	if err != nil {
		util.FatalOnError("can't create database connection", err)
		return nil
	}

	// Migrate the schema
	util.FatalOnError("can't perform auto migration", db.AutoMigrate(&logEntry{}))

	return &DatabaseWriter{
		db:               db,
		logRetentionDays: int(logRetentionDays)}
}

func (d *DatabaseWriter) Write(entry *Entry) {
	domain := util.ExtractDomain(entry.Request.Req.Question[0])
	eTLD, _ := publicsuffix.EffectiveTLDPlusOne(domain)

	d.db.Create(&logEntry{
		RequestTS:     &entry.Start,
		ClientIP:      entry.Request.ClientIP.String(),
		ClientName:    strings.Join(entry.Request.ClientNames, "; "),
		DurationMs:    entry.DurationMs,
		Reason:        entry.Response.Reason,
		ResponseType:  entry.Response.RType.String(),
		QuestionType:  dns.TypeToString[entry.Request.Req.Question[0].Qtype],
		QuestionName:  domain,
		EffectiveTLDP: eTLD,
		Answer:        util.AnswerToString(entry.Response.Res.Answer),
		ResponseCode:  dns.RcodeToString[entry.Response.Res.Rcode],
	})
}

func (d *DatabaseWriter) CleanUp() {
	deletionDate := time.Now().AddDate(0, 0, -d.logRetentionDays)

	log.PrefixedLog("database_writer").Debugf("deleting log entries with request_ts < %s", deletionDate)
	d.db.Where("request_ts < ?", deletionDate).Delete(&logEntry{})
}
