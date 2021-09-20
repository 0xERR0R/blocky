package querylog

import (
	"strings"
	"sync"
	"time"

	"gorm.io/gorm/logger"

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
	logRetentionDays uint64
	pendingEntries   []*logEntry
	lock             sync.RWMutex
	dbFlushPeriod    time.Duration
}

func NewDatabaseWriter(target string, logRetentionDays uint64, dbFlushPeriod time.Duration) *DatabaseWriter {
	return newDatabaseWriter(mysql.Open(target), logRetentionDays, dbFlushPeriod)
}

func newDatabaseWriter(target gorm.Dialector, logRetentionDays uint64, dbFlushPeriod time.Duration) *DatabaseWriter {
	db, err := gorm.Open(target, &gorm.Config{
		Logger: logger.New(
			log.Log(),
			logger.Config{
				SlowThreshold:             time.Minute,
				LogLevel:                  logger.Warn,
				IgnoreRecordNotFoundError: false,
				Colorful:                  false,
			}),
	})

	if err != nil {
		util.FatalOnError("can't create database connection", err)
		return nil
	}

	// Migrate the schema
	util.FatalOnError("can't perform auto migration", db.AutoMigrate(&logEntry{}))

	w := &DatabaseWriter{
		db:               db,
		logRetentionDays: logRetentionDays,
		dbFlushPeriod:    dbFlushPeriod}

	go w.periodicFlush()

	return w
}

func (d *DatabaseWriter) periodicFlush() {
	ticker := time.NewTicker(d.dbFlushPeriod)
	defer ticker.Stop()

	for {
		<-ticker.C
		d.doDBWrite()
	}
}

func (d *DatabaseWriter) Write(entry *Entry) {
	domain := util.ExtractDomain(entry.Request.Req.Question[0])
	eTLD, _ := publicsuffix.EffectiveTLDPlusOne(domain)

	e := &logEntry{
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
	}

	d.lock.Lock()
	defer d.lock.Unlock()

	d.pendingEntries = append(d.pendingEntries, e)
}

func (d *DatabaseWriter) CleanUp() {
	deletionDate := time.Now().AddDate(0, 0, int(-d.logRetentionDays))

	log.PrefixedLog("database_writer").Debugf("deleting log entries with request_ts < %s", deletionDate)
	d.db.Where("request_ts < ?", deletionDate).Delete(&logEntry{})
}

func (d *DatabaseWriter) doDBWrite() {
	d.lock.Lock()
	defer d.lock.Unlock()

	if len(d.pendingEntries) > 0 {
		log.Log().Tracef("%d entries to write", len(d.pendingEntries))

		// write bulk
		d.db.Create(d.pendingEntries)
		// clear the slice with pending entries
		d.pendingEntries = nil
	}
}
