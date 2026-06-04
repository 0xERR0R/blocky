//go:build mips || mipsle || mips64 || mips64le || (netbsd && !amd64) || (openbsd && !amd64 && !arm64)

// This is the exact complement of the constraint in database_writer_sqlite.go: the
// GOOS/GOARCH targets where the pure-Go SQLite driver chain (github.com/glebarez/
// sqlite -> modernc.org/sqlite) ships no generated code, e.g. linux/mips,
// linux/mipsle, netbsd/arm and openbsd/arm. Keep the two constraints in sync.

package querylog

import (
	"fmt"
	"runtime"

	"gorm.io/gorm"
)

// newSQLiteDialector is the stub compiled on platforms where the pure-Go SQLite
// driver (github.com/glebarez/sqlite -> modernc.org/sqlite -> modernc.org/libc)
// has no support, e.g. mips/mipsle. Excluding the driver keeps these release
// targets buildable; configuring the "sqlite" query log on such a build returns a
// clear error instead of failing to compile. Use the csv, mysql or postgresql
// target on these platforms.
func newSQLiteDialector(_ string) (gorm.Dialector, error) {
	return nil, fmt.Errorf("sqlite query log is not supported on this platform (%s/%s); "+
		"use the csv, mysql or postgresql query log target instead", runtime.GOOS, runtime.GOARCH)
}
