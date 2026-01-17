package taskengine

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

func getCachedLDAPPassword(ctx context.Context, db *sql.DB, box *secretBox, username string) (string, bool) {
	if db == nil || box == nil {
		return "", false
	}
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" {
		return "", false
	}
	ctxReq, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	var enc string
	var expiresAt time.Time
	err := db.QueryRowContext(ctxReq, `SELECT encrypted_password, expires_at FROM sf_ldap_password_cache WHERE username=$1`, username).Scan(&enc, &expiresAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", false
		}
		return "", false
	}
	if time.Now().UTC().After(expiresAt.UTC()) {
		_, _ = db.ExecContext(ctxReq, `DELETE FROM sf_ldap_password_cache WHERE username=$1`, username)
		return "", false
	}
	plaintext, err := box.decrypt(enc)
	if err != nil {
		return "", false
	}
	plaintext = strings.TrimSpace(plaintext)
	return plaintext, plaintext != ""
}
