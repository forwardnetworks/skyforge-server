package pglocks

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"fmt"
	"sync"
)

func DeploymentAdvisoryLockKey(ownerID, deploymentID string) int64 {
	sum := sha256.Sum256(fmt.Appendf(nil, "%s:%s", ownerID, deploymentID))
	u := binary.LittleEndian.Uint64(sum[:8])
	return int64(u)
}

func UserAdvisoryLockKey(ownerID string) int64 {
	sum := sha256.Sum256(fmt.Appendf(nil, "%s:__owner__", ownerID))
	u := binary.LittleEndian.Uint64(sum[:8])
	return int64(u)
}

func KeyFromString(s string) int64 {
	sum := sha256.Sum256([]byte(s))
	u := binary.LittleEndian.Uint64(sum[:8])
	return int64(u)
}

// AdvisoryLock is a session-bound PostgreSQL advisory lock.
//
// PostgreSQL advisory locks are bound to the DB session (connection), so lock
// and unlock operations must run on the same underlying connection.
type AdvisoryLock struct {
	conn *sql.Conn
	key  int64
	once sync.Once
}

func TryAdvisoryLock(ctx context.Context, db *sql.DB, key int64) (*AdvisoryLock, bool, error) {
	if db == nil {
		return nil, false, fmt.Errorf("db unavailable")
	}
	conn, err := db.Conn(ctx)
	if err != nil {
		return nil, false, err
	}
	var ok bool
	if err := conn.QueryRowContext(ctx, `SELECT pg_try_advisory_lock($1)`, key).Scan(&ok); err != nil {
		_ = conn.Close()
		return nil, false, err
	}
	if !ok {
		_ = conn.Close()
		return nil, false, nil
	}
	return &AdvisoryLock{conn: conn, key: key}, true, nil
}

func (l *AdvisoryLock) Unlock(ctx context.Context) error {
	if l == nil {
		return nil
	}
	var unlockErr error
	l.once.Do(func() {
		if l.conn == nil {
			return
		}
		var ok bool
		unlockErr = l.conn.QueryRowContext(ctx, `SELECT pg_advisory_unlock($1)`, l.key).Scan(&ok)
		if unlockErr == nil && !ok {
			unlockErr = fmt.Errorf("advisory lock not held for key %d", l.key)
		}
		if closeErr := l.conn.Close(); unlockErr == nil && closeErr != nil {
			unlockErr = closeErr
		}
		l.conn = nil
	})
	if unlockErr != nil {
		return unlockErr
	}
	return nil
}
