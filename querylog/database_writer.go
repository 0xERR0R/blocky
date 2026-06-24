package querylog

import (
	"context"
	"fmt"
	"log/slog"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"gorm.io/gorm/logger"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/log"
	"github.com/hashicorp/go-multierror"

	"github.com/0xERR0R/blocky/util"

	"golang.org/x/net/publicsuffix"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// slogPrintf wraps a *slog.Logger to satisfy gorm's logger.Writer interface.
type slogPrintf struct {
	l *slog.Logger
}

func (s slogPrintf) Printf(msg string, args ...any) {
	s.l.Info(fmt.Sprintf(msg, args...))
}

type logEntry struct {
	RequestTS     time.Time `gorm:"not null;index"`
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

func NewDatabaseWriter(ctx context.Context, dbType config.QueryLogType, target string, logRetentionDays uint64,
	dbFlushPeriod time.Duration,
) (*DatabaseWriter, error) {
	switch dbType { //nolint:exhaustive // non-database query-log types are handled in GetQueryLoggingWriter
	case config.QueryLogTypeMysql:
		return newDatabaseWriter(ctx, mysql.Open(target), logRetentionDays, dbFlushPeriod, dbType)
	case config.QueryLogTypePostgresql, config.QueryLogTypeTimescale:
		return newDatabaseWriter(ctx, postgres.Open(target), logRetentionDays, dbFlushPeriod, dbType)
	case config.QueryLogTypeSqlite:
		dialector, err := newSQLiteDialector(target)
		if err != nil {
			return nil, err
		}

		return newDatabaseWriter(ctx, dialector, logRetentionDays, dbFlushPeriod, dbType)
	}

	return nil, fmt.Errorf("incorrect database type provided: %s", dbType)
}

func newDatabaseWriter(ctx context.Context, target gorm.Dialector, logRetentionDays uint64,
	dbFlushPeriod time.Duration, dbType config.QueryLogType,
) (*DatabaseWriter, error) {
	db, err := gorm.Open(target, &gorm.Config{
		Logger: logger.New(
			slogPrintf{log.PrefixedLog("database_writer")},
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

	// SQLite is a single local file: a write holds an exclusive lock on the whole
	// database, so letting the pool open several connections only turns blocky's own
	// concurrent access (the periodic flush vs. the retention cleanup) into
	// SQLITE_BUSY errors. Serialize through one connection instead; external readers
	// use their own connections and are unaffected.
	if dbType == config.QueryLogTypeSqlite {
		sqlDB, err := db.DB()
		if err != nil {
			return nil, fmt.Errorf("can't access sqlite connection pool: %w", err)
		}

		sqlDB.SetMaxOpenConns(1)
	}

	// Migrate the schema
	if err := databaseMigration(db, dbType, logRetentionDays); err != nil {
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

func databaseMigration(db *gorm.DB, dbType config.QueryLogType, logRetentionDays uint64) error {
	if err := db.AutoMigrate(&logEntry{}); err != nil {
		return fmt.Errorf("failed to auto-migrate database schema for querylog: %w", err)
	}

	tableName := db.NamingStrategy.TableName(reflect.TypeFor[logEntry]().Name())

	// create unmapped primary key
	switch dbType { //nolint:exhaustive // only database-backed targets reach migration
	case config.QueryLogTypeSqlite:
		// SQLite gives every table an implicit auto-incrementing rowid that already
		// acts as the primary key, so unlike the other targets no extra id column is
		// added here (and SQLite cannot ALTER TABLE ... ADD a PRIMARY KEY column).

	case config.QueryLogTypeMysql:
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

	case config.QueryLogTypePostgresql:
		return db.Exec("ALTER TABLE " + tableName + " ADD column if not exists id bigserial primary key").Error

	case config.QueryLogTypeTimescale:
		requestTSColName := db.NamingStrategy.ColumnName(reflect.TypeFor[logEntry]().Name(), "RequestTS")

		// Create a Timescale hypertable
		tx := db.Exec(`SELECT create_hypertable(
			'` + tableName + `',
			by_range('` + requestTSColName + `'),
			if_not_exists => TRUE
		)`)
		if tx.Error != nil {
			return tx.Error
		}

		// Create a retention policy for the hypertable
		tx = db.Exec(`SELECT add_retention_policy(
			'` + tableName + `',
			drop_after => INTERVAL '` + strconv.FormatUint(logRetentionDays, 10) + ` days',
			if_not_exists => TRUE
		)`)
		if tx.Error != nil {
			return tx.Error
		}
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
		RequestTS:     entry.Start,
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
		Hostname:      entry.BlockyInstance,
	}

	d.lock.Lock()
	defer d.lock.Unlock()

	d.pendingEntries = append(d.pendingEntries, e)
}

func (d *DatabaseWriter) CleanUp() {
	deletionDate := time.Now().AddDate(0, 0, int(-d.logRetentionDays)) //nolint:gosec // G115: correct via two's complement

	log.PrefixedLog("database_writer").Debug(fmt.Sprintf("deleting log entries with request_ts < %s", deletionDate))
	d.db.Where("request_ts < ?", deletionDate).Delete(&logEntry{})
}

func (d *DatabaseWriter) doDBWrite() error {
	d.lock.Lock()
	defer d.lock.Unlock()

	var err *multierror.Error

	if len(d.pendingEntries) > 0 {
		log.Log().Debug("entries to write", slog.Int("count", len(d.pendingEntries)))

		const bulkSize = 100

		for i := 0; i < len(d.pendingEntries); i += bulkSize {
			j := min(i+bulkSize, len(d.pendingEntries))
			// write bulk
			tx := d.db.Create(d.pendingEntries[i:j])
			err = multierror.Append(err, tx.Error)
		}

		// clear the slice with pending entries
		d.pendingEntries = nil

		if multiErr := err.ErrorOrNil(); multiErr != nil {
			return fmt.Errorf("failed to write querylog entries to database: %w", multiErr)
		}
	}

	return nil
}
