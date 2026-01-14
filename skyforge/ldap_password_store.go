package skyforge

import (
	"context"
	"database/sql"
	"time"
)

func upsertLDAPPasswordCache(ctx context.Context, db *sql.DB, username, encrypted string, expiresAt time.Time) error {
	if db == nil {
		return sql.ErrConnDone
	}
	_, err := db.ExecContext(ctx, `
INSERT INTO sf_ldap_password_cache (username, encrypted_password, expires_at, updated_at)
VALUES ($1, $2, $3, now())
ON CONFLICT (username)
DO UPDATE SET encrypted_password = EXCLUDED.encrypted_password, expires_at = EXCLUDED.expires_at, updated_at = now()
`, username, encrypted, expiresAt.UTC())
	return err
}

func getLDAPPasswordCache(ctx context.Context, db *sql.DB, username string) (enc string, expiresAt time.Time, ok bool, err error) {
	if db == nil {
		return "", time.Time{}, false, sql.ErrConnDone
	}
	err = db.QueryRowContext(ctx, `
SELECT encrypted_password, expires_at
FROM sf_ldap_password_cache
WHERE username = $1
`, username).Scan(&enc, &expiresAt)
	if err == sql.ErrNoRows {
		return "", time.Time{}, false, nil
	}
	if err != nil {
		return "", time.Time{}, false, err
	}
	if time.Now().UTC().After(expiresAt.UTC()) {
		_, _ = db.ExecContext(ctx, `DELETE FROM sf_ldap_password_cache WHERE username = $1`, username)
		return "", time.Time{}, false, nil
	}
	return enc, expiresAt, true, nil
}

func deleteLDAPPasswordCache(ctx context.Context, db *sql.DB, username string) error {
	if db == nil {
		return sql.ErrConnDone
	}
	_, err := db.ExecContext(ctx, `DELETE FROM sf_ldap_password_cache WHERE username = $1`, username)
	return err
}
