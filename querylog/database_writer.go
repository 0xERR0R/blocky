package querylog

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/avast/retry-go/v5"
	mysqldriver "github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/publicsuffix"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/log"
	"github.com/0xERR0R/blocky/util"
)

const (
	dbBatchSize = 1000

	// dbStatementRows is the most entries one INSERT carries. Larger statements cost
	// more per row: the SQLite driver binds each parameter by scanning all of them.
	dbStatementRows = 100

	// dbMaxPendingBytes bounds the memory entries hold while the database is slow or down.
	dbMaxPendingBytes = 32 << 20

	// dbClientNameMaxRunes cuts client names, for every database, to the size of the
	// indexed client_name column GORM creates on MySQL: the smallest any of them takes.
	dbClientNameMaxRunes = 191

	// dbWriteTimeout bounds one write, and one attempt to connect.
	dbWriteTimeout  = 30 * time.Second
	dbRetryDelay    = time.Second
	dbRetryMaxDelay = 30 * time.Second
)

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

// DatabaseWriter buffers entries in memory and writes them to the database in
// batches from a single background goroutine, so Write never waits on the
// database. A failed batch is retried until it's written, except for rows the
// database refuses; the database being unreachable at startup is retried the same
// way. A batch interrupted at commit may be written twice.
type DatabaseWriter struct {
	dialect          dialect
	dbType           config.QueryLogType
	logRetentionDays uint64
	dbFlushPeriod    time.Duration
	maxPendingBytes  int
	writeTimeout     time.Duration

	// db is nil until the background goroutine has connected and migrated the schema.
	db atomic.Pointer[gorm.DB]

	// pending holds the entries not yet written, including the batch being written.
	// Shutdown drops what is left of them and sets closed.
	lock         sync.Mutex
	pending      []*logEntry
	pendingBytes int
	closed       bool

	// dropped and refused count what the log reports, at every power of ten.
	dropped atomic.Uint64
	refused atomic.Uint64

	// wake tells the background goroutine a full batch is pending.
	wake chan struct{}

	stopRun context.CancelFunc
	runDone chan struct{}
}

func NewDatabaseWriter(ctx context.Context, dbType config.QueryLogType, target string, logRetentionDays uint64,
	dbFlushPeriod time.Duration,
) (*DatabaseWriter, error) {
	// The connection strings are parsed here, not when connecting: a malformed one fails
	// the writer's creation, while an unreachable database is retried in the background.
	switch dbType { //nolint:exhaustive // non-database query-log types are handled in GetQueryLoggingWriter
	case config.QueryLogTypeMysql:
		connector, err := mysqldriver.MySQLDriver{}.OpenConnector(target)
		if err != nil {
			return nil, fmt.Errorf("can't create database connection: %w", err)
		}

		return newDatabaseWriter(ctx, mysqlDialect(connector, target), logRetentionDays, dbFlushPeriod, dbType), nil
	case config.QueryLogTypePostgresql, config.QueryLogTypeTimescale:
		if _, err := pgx.ParseConfig(target); err != nil {
			return nil, fmt.Errorf("can't create database connection: %w", err)
		}

		// A dialector for each attempt: GORM's keeps what it adds to its options while opening.
		perAttempt := func(context.Context) gorm.Dialector { return postgres.Open(target) }

		return newDatabaseWriter(ctx, perAttempt, logRetentionDays, dbFlushPeriod, dbType), nil
	case config.QueryLogTypeSqlite:
		dialector, err := newSQLiteDialector(target)
		if err != nil {
			return nil, err
		}

		return newDatabaseWriter(ctx, fixedDialect(dialector), logRetentionDays, dbFlushPeriod, dbType), nil
	}

	return nil, fmt.Errorf("incorrect database type provided: %s", dbType)
}

// dialect returns the dialector for one connection attempt, which ends with ctx.
type dialect func(ctx context.Context) gorm.Dialector

func fixedDialect(target gorm.Dialector) dialect {
	return func(context.Context) gorm.Dialector { return target }
}

// mysqlDialect ends GORM's MySQL setup with the connection attempt. GORM asks for the
// server version with context.Background(), so a server that stops answering would
// hold the writer until the connection died.
func mysqlDialect(connector driver.Connector, dsn string) dialect {
	return func(ctx context.Context) gorm.Dialector {
		pool := sql.OpenDB(connector)
		//nolint:forcetypeassert // mysql.New always returns a *mysql.Dialector
		target := mysql.New(mysql.Config{Conn: attemptPool{pool, ctx}, DSN: dsn}).(*mysql.Dialector)

		return mysqlDialector{target, pool}
	}
}

// mysqlDialector sets GORM up through an attemptPool, then gives it the pool itself.
type mysqlDialector struct {
	*mysql.Dialector

	pool *sql.DB
}

func (d mysqlDialector) Initialize(db *gorm.DB) error {
	if err := d.Dialector.Initialize(db); err != nil {
		_ = d.pool.Close()

		return err
	}

	db.ConnPool = d.pool

	return nil
}

// attemptPool runs GORM's version query under the connection attempt's context.
type attemptPool struct {
	*sql.DB

	ctx context.Context //nolint:containedctx // Initialize takes none
}

func (p attemptPool) QueryRowContext(_ context.Context, query string, args ...any) *sql.Row {
	return p.DB.QueryRowContext(p.ctx, query, args...) //nolint:contextcheck // GORM passes context.Background()
}

func newDatabaseWriter(ctx context.Context, target dialect, logRetentionDays uint64,
	dbFlushPeriod time.Duration, dbType config.QueryLogType,
) *DatabaseWriter {
	runCtx, stopRun := context.WithCancel(ctx)

	w := &DatabaseWriter{
		dialect:          target,
		dbType:           dbType,
		logRetentionDays: logRetentionDays,
		dbFlushPeriod:    dbFlushPeriod,
		maxPendingBytes:  dbMaxPendingBytes,
		writeTimeout:     dbWriteTimeout,
		wake:             make(chan struct{}, 1),
		stopRun:          stopRun,
		runDone:          make(chan struct{}),
	}

	go w.run(runCtx)

	return w
}

func dbLogger() *logrus.Entry {
	return log.PrefixedLog("database_writer")
}

// openDatabase connects to the database, giving up after dbWriteTimeout, and migrates
// the schema, giving up when ctx is done.
func openDatabase(
	ctx context.Context, target dialect, dbType config.QueryLogType, logRetentionDays uint64,
) (*gorm.DB, error) {
	connectCtx, cancel := context.WithTimeout(ctx, dbWriteTimeout)
	defer cancel()

	db, err := gorm.Open(target(connectCtx), &gorm.Config{
		// Its ping has no context; the PingContext below does the same with a deadline.
		DisableAutomaticPing: true,
		// The writer logs failures itself; GORM's logger would print every failed
		// INSERT with all its values.
		Logger: logger.Discard,
	})
	if err != nil {
		return nil, fmt.Errorf("can't create database connection: %w", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("can't access database connection pool: %w", err)
	}

	// SQLite is a single local file: a write holds an exclusive lock on the whole
	// database, so letting the pool open several connections only turns blocky's own
	// concurrent access (the periodic flush vs. the retention cleanup) into
	// SQLITE_BUSY errors. Serialize through one connection instead; external readers
	// use their own connections and are unaffected.
	if dbType == config.QueryLogTypeSqlite {
		sqlDB.SetMaxOpenConns(1)
	}

	if err := sqlDB.PingContext(connectCtx); err != nil {
		_ = sqlDB.Close()

		return nil, fmt.Errorf("can't create database connection: %w", err)
	}

	// No deadline here: migrating a large existing table can take a while.
	if err := databaseMigration(db.WithContext(ctx), dbType, logRetentionDays); err != nil {
		_ = sqlDB.Close()

		return nil, fmt.Errorf("can't perform auto migration: %w", err)
	}

	return db, nil
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

// run connects, then writes full batches as they fill and everything pending every
// flush period, until ctx is done.
func (d *DatabaseWriter) run(ctx context.Context) {
	defer close(d.runDone)

	err := retry.New(retryOptions(ctx, "connect to the query log database")...).Do(
		func() error {
			db, err := openDatabase(ctx, d.dialect, d.dbType, d.logRetentionDays)
			if err == nil {
				d.db.Store(db)
			}

			return err
		},
	)
	if err != nil {
		return // ctx is done
	}

	ticker := time.NewTicker(d.dbFlushPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-d.wake:
			_ = d.flush(ctx, true)
		case <-ticker.C:
			_ = d.flush(ctx, false)
		case <-ctx.Done():
			return
		}
	}
}

// flush writes the pending entries in full batches and, unless fullOnly, one last
// smaller batch; what arrives meanwhile waits for the next flush. Entries stay pending
// until they're written, so whatever is left when ctx ends is still there for Shutdown.
func (d *DatabaseWriter) flush(ctx context.Context, fullOnly bool) error {
	for {
		d.lock.Lock()
		batch := slices.Clone(d.pending[:min(len(d.pending), dbBatchSize)])
		d.lock.Unlock()

		if len(batch) == 0 || (fullOnly && len(batch) < dbBatchSize) {
			return nil
		}

		done, err := d.ship(ctx, batch)
		d.removeDone(done)

		if err != nil || len(batch) < dbBatchSize {
			return err
		}
	}
}

// removeDone removes the first n pending entries, which were written or refused.
func (d *DatabaseWriter) removeDone(n int) {
	d.lock.Lock()
	defer d.lock.Unlock()

	if d.closed {
		return // a Shutdown that timed out has dropped them already
	}

	d.pendingBytes -= sizeOf(d.pending[:n])
	clear(d.pending[:n]) // don't keep them reachable through the backing array
	d.pending = d.pending[n:]
}

// size estimates the memory an entry holds.
func (e *logEntry) size() int {
	return int(reflect.TypeFor[logEntry]().Size()) + len(e.ClientIP) + len(e.ClientName) + len(e.Reason) +
		len(e.ResponseType) + len(e.QuestionType) + len(e.QuestionName) + len(e.EffectiveTLDP) + len(e.Answer) +
		len(e.ResponseCode) + len(e.Hostname)
}

func sizeOf(entries []*logEntry) int {
	n := 0
	for _, e := range entries {
		n += e.size()
	}

	return n
}

// ship writes batch, retrying until ctx ends, and returns how many of its first
// entries are done: written, or refused and dropped. When the database still takes a
// plain row but not this batch, ship splits the batch until the rows it refuses are
// found, so they can't hold up the rest.
func (d *DatabaseWriter) ship(ctx context.Context, batch []*logEntry) (int, error) {
	err := retry.New(retryOptions(ctx, fmt.Sprintf("write %d query log entries", len(batch)))...).Do(
		func() error {
			return d.attempt(ctx, batch)
		},
	)

	switch {
	case err == nil:
		return len(batch), nil
	case retry.IsRecoverable(err):
		return 0, err // ctx is done
	case len(batch) == 1:
		CountDropped(DropReasonRejected, 1)

		if n := d.refused.Add(1); isPowerOfTen(n) {
			dbLogger().Errorf("the database refused %d query log entries so far, dropping them; latest: %v", n, err)
		}

		return 1, nil
	}

	mid := len(batch) / 2

	done, err := d.ship(ctx, batch[:mid])
	if err != nil {
		return done, err
	}

	done, err = d.ship(ctx, batch[mid:])

	return mid + done, err
}

// attempt tries to write batch once. Its error is unrecoverable when a larger batch is
// to be split, or a lone row dropped.
func (d *DatabaseWriter) attempt(ctx context.Context, batch []*logEntry) error {
	err := d.insert(ctx, batch)

	switch {
	case err == nil:
		return nil
	case len(batch) > 1:
		// The batch is at fault, not the database, when a plain row still goes in.
		if !d.acceptsPlainRow(ctx) {
			return err
		}
	default:
		// A lone row is at fault when the server refuses it twice, the second time at
		// once in case the first refusal was passing (e.g. a server restarting), and
		// still takes a plain row. Failing any other way (no connection, a timeout, a
		// lock) says nothing about the row.
		if !refusedByServer(err) {
			return err
		}

		if err = d.insert(ctx, batch); !refusedByServer(err) || !d.acceptsPlainRow(ctx) {
			return err
		}
	}

	return retry.Unrecoverable(err)
}

func (d *DatabaseWriter) insert(ctx context.Context, batch []*logEntry) error {
	ctx, cancel := context.WithTimeout(ctx, d.writeTimeout)
	defer cancel()

	// GORM runs the INSERTs in one transaction: the batch is written whole or not at all.
	return d.db.Load().WithContext(ctx).CreateInBatches(batch, dbStatementRows).Error
}

// refusedByServer reports whether err is the server's own answer to a statement,
// other than that it gave up on a lock or cancelled the statement. Only such an answer
// can be about the rows; a failed connection or a timeout isn't.
func refusedByServer(err error) bool {
	var (
		pgErr *pgconn.PgError
		myErr *mysqldriver.MySQLError
	)

	switch {
	case errors.As(err, &pgErr):
		// lock_not_available, query_canceled, and class 40 (transaction rollback: deadlock, ...)
		return pgErr.Code != "55P03" && pgErr.Code != "57014" && !strings.HasPrefix(pgErr.Code, "40")
	case errors.As(err, &myErr):
		const lockWaitTimeout, deadlock = 1205, 1213

		return myErr.Number != lockWaitTimeout && myErr.Number != deadlock
	}

	return false
}

// acceptsPlainRow reports whether the database takes a row of empty fields right
// now, rolling it back (its id is still used up). When it doesn't, the database or
// its schema is failing, not the rows being written.
func (d *DatabaseWriter) acceptsPlainRow(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, d.writeTimeout)
	defer cancel()

	tx := d.db.Load().WithContext(ctx).Begin()
	defer tx.Rollback()

	return tx.Create(&logEntry{RequestTS: time.Now()}).Error == nil
}

// retryOptions retries forever, backing off, until ctx ends.
func retryOptions(ctx context.Context, action string) []retry.Option {
	return []retry.Option{
		retry.Context(ctx),
		retry.UntilSucceeded(),
		retry.DelayType(retry.BackOffDelay),
		retry.Delay(dbRetryDelay),
		retry.MaxDelay(dbRetryMaxDelay),
		retry.OnRetry(func(_ uint, err error) {
			if ctx.Err() == nil { // else there is no retry
				dbLogger().Warnf("can't %s, retrying: %v", action, err)
			}
		}),
	}
}

// storableClientName returns name as valid UTF-8 without control characters (NUL
// among them), at most dbClientNameMaxRunes long: what PostgreSQL and a utf8mb4 MySQL
// store and index. A client ID is the client's to choose: a DoH path, a DoT server name.
// The result is a copy, so that a short name doesn't keep a long server name in memory.
func storableClientName(name string) string {
	name = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}

		return r
	}, strings.ToValidUTF8(name, ""))

	if utf8.RuneCountInString(name) > dbClientNameMaxRunes {
		name = string([]rune(name)[:dbClientNameMaxRunes])
	}

	return strings.Clone(name)
}

func (d *DatabaseWriter) Write(entry *LogEntry) {
	domain := util.ExtractDomainOnly(entry.QuestionName)
	eTLD, _ := publicsuffix.EffectiveTLDPlusOne(domain)

	e := &logEntry{
		RequestTS:     entry.Start,
		ClientIP:      entry.ClientIP,
		ClientName:    storableClientName(strings.Join(entry.ClientNames, "; ")),
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

	size := e.size()

	d.lock.Lock()

	if d.pendingBytes+size > d.maxPendingBytes {
		d.lock.Unlock()
		CountDropped(DropReasonBufferFull, 1)

		if n := d.dropped.Add(1); isPowerOfTen(n) {
			dbLogger().Warnf("query log buffer (%d bytes) full (database slow or unreachable), dropped %d entries so far",
				d.maxPendingBytes, n)
		}

		return
	}

	d.pending = append(d.pending, e)
	d.pendingBytes += size
	full := len(d.pending) >= dbBatchSize

	d.lock.Unlock()

	if full {
		select {
		case d.wake <- struct{}{}:
		default:
		}
	}
}

func (d *DatabaseWriter) CleanUp() {
	db := d.db.Load()
	if db == nil {
		return // not connected yet; the next cleanup catches up
	}

	deletionDate := time.Now().AddDate(0, 0, int(-d.logRetentionDays)) //nolint:gosec // G115: correct via two's complement

	dbLogger().Debugf("deleting log entries with request_ts < %s", deletionDate)

	if err := db.Where("request_ts < ?", deletionDate).Delete(&logEntry{}).Error; err != nil {
		dbLogger().Errorf("can't delete old query log entries: %v", err)
	}
}

// Shutdown stops the background goroutine and writes the pending entries, retrying
// until ctx ends. Entries left unwritten are dropped and counted.
func (d *DatabaseWriter) Shutdown(ctx context.Context) error {
	d.stopRun()

	// On a goroutine: a write the driver can't interrupt (a MySQL COMMIT, say) mustn't
	// hold Shutdown past ctx.
	flushed := make(chan error, 1)

	go func() {
		<-d.runDone

		// Don't start connecting now: the background goroutine has been retrying all along.
		if d.db.Load() == nil {
			flushed <- errors.New("never connected to the database")

			return
		}

		flushed <- d.flush(ctx, false)
	}()

	select {
	case err := <-flushed:
		return d.dropPending(err)
	case <-ctx.Done():
		return d.dropPending(ctx.Err())
	}
}

// dropPending drops and counts the entries still pending, and closes the writer. It
// returns an error if it dropped any.
func (d *DatabaseWriter) dropPending(cause error) error {
	d.lock.Lock()
	n := len(d.pending)
	d.pending, d.pendingBytes, d.closed = nil, 0, true
	d.lock.Unlock()

	if n == 0 {
		return nil
	}

	CountDropped(DropReasonShutdown, n)

	err := fmt.Errorf("dropped %d query log entries not written before shutdown", n)
	if cause != nil {
		err = fmt.Errorf("%w: %w", err, cause)
	}

	return err
}
