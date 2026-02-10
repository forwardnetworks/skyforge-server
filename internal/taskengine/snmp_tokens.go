package taskengine

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// ensureUserSnmpTrapToken returns the per-user SNMPv2c community used for both polling and traps.
// The value is stored encrypted in sf_snmp_trap_tokens.
func (e *Engine) ensureUserSnmpTrapToken(ctx context.Context, username string) (string, error) {
	if e == nil || e.db == nil || e.box == nil {
		return "", fmt.Errorf("engine unavailable")
	}
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" {
		return "", fmt.Errorf("username is required")
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	var enc sql.NullString
	if err := e.db.QueryRowContext(ctx, `SELECT community FROM sf_snmp_trap_tokens WHERE username=$1`, username).Scan(&enc); err != nil {
		if err != sql.ErrNoRows {
			return "", err
		}
		enc.Valid = false
	}
	if enc.Valid && strings.TrimSpace(enc.String) != "" {
		plain, err := e.box.decrypt(enc.String)
		if err == nil && strings.TrimSpace(plain) != "" {
			return strings.TrimSpace(plain), nil
		}
		// If we can't decrypt, delete and recreate.
		_, _ = e.db.ExecContext(ctx, `DELETE FROM sf_snmp_trap_tokens WHERE username=$1`, username)
	}

	comm, err := generateSnmpCommunity(username)
	if err != nil {
		return "", err
	}
	encOut, err := e.box.encrypt(comm)
	if err != nil {
		return "", err
	}
	_, err = e.db.ExecContext(ctx, `INSERT INTO sf_snmp_trap_tokens (username, community, updated_at)
VALUES ($1,$2,now())
ON CONFLICT (username) DO UPDATE SET community=excluded.community, updated_at=now()`, username, encOut)
	if err != nil {
		return "", err
	}
	return comm, nil
}

func generateSnmpCommunity(username string) (string, error) {
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" {
		return "", fmt.Errorf("username is required")
	}
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "sf-" + username + "-" + hex.EncodeToString(b), nil
}
