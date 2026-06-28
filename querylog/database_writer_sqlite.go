//go:build !mips && !mipsle && !mips64 && !mips64le && !loong64 && !(netbsd && !amd64) && !(openbsd && !amd64 && !arm64)

// SQLite support is compiled in only on the GOOS/GOARCH targets supported by the
// pure-Go driver chain (github.com/glebarez/sqlite -> modernc.org/sqlite ->
// modernc.org/libc). modernc ships no MIPS support at all and only a subset of the
// BSD architectures (netbsd/amd64, openbsd/amd64+arm64), so the remaining release
// targets compile the stub in database_writer_sqlite_unsupported.go instead. This
// keeps the cross-compiled release build working (without SQLite query log there).
// Revisit this list when the modernc.org/sqlite dependency is upgraded.

package querylog

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

// sqliteBusyTimeoutMs is the SQLite busy_timeout (in ms) applied to the query-log
// connection so transient lock contention with external readers is retried, not failed.
const sqliteBusyTimeoutMs = 5000

// sqliteDirPermission is the permission used when creating the parent directory of the sqlite database file.
const sqliteDirPermission os.FileMode = 0o750

// newSQLiteDialector validates the target path, ensures its parent directory exists
// and returns a gorm dialector backed by the pure-Go (modernc) SQLite driver.
//
// The pure-Go driver (github.com/glebarez/sqlite -> modernc.org/sqlite ->
// modernc.org/libc) only supports a subset of the release build targets, so this
// implementation is compiled in everywhere except those platforms. See
// database_writer_sqlite_unsupported.go for the stub used on the remaining targets
// (e.g. mips/mipsle).
func newSQLiteDialector(target string) (gorm.Dialector, error) {
	if target == "" {
		return nil, errors.New("sqlite query log requires a target file path")
	}

	if err := os.MkdirAll(filepath.Dir(target), sqliteDirPermission); err != nil {
		return nil, fmt.Errorf("can't create directory for sqlite database: %w", err)
	}

	return sqlite.Open(buildSQLiteDSN(target)), nil
}

// buildSQLiteDSN turns a filesystem path into a modernc/glebarez SQLite DSN with
// WAL journaling enabled. The "file:" prefix selects SQLite's URI filename mode,
// the canonical form for passing connection options as query parameters. Because
// that mode runs the path through SQLite's URI parser, the path is percent-encoded
// first: otherwise a path containing "?" or "#" would be truncated (silently
// opening a different file, possibly without WAL) and "%xx" would be decoded into
// a different path. "%" is encoded first as it is the escape character itself;
// strings.Replacer never re-scans its own output, so the inserted "%25" is safe.
func buildSQLiteDSN(path string) string {
	encodedPath := strings.NewReplacer("%", "%25", "?", "%3F", "#", "%23").Replace(path)

	return fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(%d)", encodedPath, sqliteBusyTimeoutMs)
}
