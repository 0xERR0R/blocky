package querylog

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"time"

	"gorm.io/gorm/logger"

	"github.com/0xERR0R/blocky/log"
	"github.com/hashicorp/go-multierror"

	"github.com/0xERR0R/blocky/util"

	"golang.org/x/net/publicsuffix"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
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
	Hostname      string
}

type DatabaseWriter struct {
	db               *gorm.DB
	logRetentionDays uint64
	pendingEntries   []*logEntry
	lock             sync.RWMutex
	dbFlushPeriod    time.Duration
}

func NewDatabaseWriter(ctx context.Context, dbType, target string, logRetentionDays uint64,
	dbFlushPeriod time.Duration,
) (*DatabaseWriter, error) {
	switch dbType {
	case "mysql":
		return newDatabaseWriter(ctx, mysql.Open(target), logRetentionDays, dbFlushPeriod)
	case "postgresql":
		return newDatabaseWriter(ctx, postgres.Open(target), logRetentionDays, dbFlushPeriod)
	}

	return nil, fmt.Errorf("incorrect database type provided: %s", dbType)
}

func newDatabaseWriter(ctx context.Context, target gorm.Dialector, logRetentionDays uint64,
	dbFlushPeriod time.Duration,
) (*DatabaseWriter, error) {
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
		return nil, fmt.Errorf("can't create database connection: %w", err)
	}

	// Migrate the schema
	if err := databaseMigration(db); err != nil {
		return nil, fmt.Errorf("can't perform auto migration: %w", err)
	}

	w := &DatabaseWriter{
		db:               db,
		logRetentionDays: logRetentionDays,
		dbFlushPeriod:    dbFlushPeriod,
	}

	go w.periodicFlush(ctx)

	return w, nil
}

func databaseMigration(db *gorm.DB) error {
	if err := db.AutoMigrate(&logEntry{}); err != nil {
		return err
	}

	tableName := db.NamingStrategy.TableName(reflect.TypeOf(logEntry{}).Name())

	// create unmapped primary key
	switch db.Config.Name() {
	case "mysql":
		tx := db.Exec("ALTER TABLE `" + tableName + "` ADD `id` INT PRIMARY KEY AUTO_INCREMENT")
		if tx.Error != nil {
			// mysql doesn't support "add column if not exist"
			if strings.Contains(tx.Error.Error(), "1060") {
				// error 1060: duplicate column name
				// ignore it
				return nil
			}

			return tx.Error
		}

	case "postgres":
		return db.Exec("ALTER TABLE " + tableName + " ADD column if not exists id serial primary key").Error
	}

	return nil
}

func (d *DatabaseWriter) periodicFlush(ctx context.Context) {
	ticker := time.NewTicker(d.dbFlushPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			err := d.doDBWrite()

			util.LogOnError(ctx, "can't write entries to the database: ", err)

		case <-ctx.Done():
			return
		}
	}
}

func (d *DatabaseWriter) Write(entry *LogEntry) {
	domain := util.ExtractDomainOnly(entry.QuestionName)
	eTLD, _ := publicsuffix.EffectiveTLDPlusOne(domain)

	e := &logEntry{
		RequestTS:     &entry.Start,
		ClientIP:      entry.ClientIP,
		ClientName:    strings.Join(entry.ClientNames, "; "),
		DurationMs:    entry.DurationMs,
		Reason:        entry.ResponseReason,
		ResponseType:  entry.ResponseType,
		QuestionType:  entry.QuestionType,
		QuestionName:  domain,
		EffectiveTLDP: eTLD,
		Answer:        entry.Answer,
		ResponseCode:  entry.ResponseCode,
		Hostname:      util.HostnameString(),
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

func (d *DatabaseWriter) doDBWrite() error {
	d.lock.Lock()
	defer d.lock.Unlock()

	var err *multierror.Error

	if len(d.pendingEntries) > 0 {
		log.Log().Tracef("%d entries to write", len(d.pendingEntries))

		const bulkSize = 100

		for i := 0; i < len(d.pendingEntries); i += bulkSize {
			j := i + bulkSize
			if j > len(d.pendingEntries) {
				j = len(d.pendingEntries)
			}
			// write bulk
			tx := d.db.Create(d.pendingEntries[i:j])
			err = multierror.Append(err, tx.Error)
		}

		// clear the slice with pending entries
		d.pendingEntries = nil

		return err.ErrorOrNil()
	}

	return nil
}
