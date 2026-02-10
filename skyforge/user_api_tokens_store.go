package skyforge

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"encore.dev/beta/errs"
)

type userAPITokenRecord struct {
	ID         string
	Username   string
	Name       string
	Prefix     string
	UsedCount  int64
	CreatedAt  time.Time
	LastUsedAt sql.NullTime
	RevokedAt  sql.NullTime
}

func generateUserAPIToken() (token string, prefix string, hash []byte, err error) {
	// 32 bytes gives 256 bits of entropy; base64url expands this to ~43 chars.
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", "", nil, err
	}
	raw := base64.RawURLEncoding.EncodeToString(b[:])
	token = "sf_pat_" + raw
	if len(token) > 16 {
		prefix = token[:16]
	} else {
		prefix = token
	}
	sum := sha256.Sum256([]byte(token))
	return token, prefix, sum[:], nil
}

func createUserAPIToken(ctx context.Context, db *sql.DB, username, name string) (*userAPITokenRecord, string, error) {
	if db == nil {
		return nil, "", errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	username = strings.ToLower(strings.TrimSpace(username))
	name = strings.TrimSpace(name)
	if username == "" {
		return nil, "", errs.B().Code(errs.InvalidArgument).Msg("username required").Err()
	}
	if name == "" {
		name = "API token"
	}

	token, prefix, hash, err := generateUserAPIToken()
	if err != nil {
		return nil, "", errs.B().Code(errs.Unavailable).Msg("token generation failed").Err()
	}

	id := uuid.NewString()
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	_, err = db.ExecContext(ctx, `
INSERT INTO sf_user_api_tokens (id, username, name, token_prefix, token_hash, created_at)
VALUES ($1,$2,$3,$4,$5,now())
`, id, username, name, prefix, hash)
	if err != nil {
		return nil, "", err
	}

	rec := &userAPITokenRecord{
		ID:        id,
		Username:  username,
		Name:      name,
		Prefix:    prefix,
		UsedCount: 0,
		CreatedAt: time.Now(),
	}
	return rec, token, nil
}

func listUserAPITokens(ctx context.Context, db *sql.DB, username string) ([]userAPITokenRecord, error) {
	if db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("username required").Err()
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	rows, err := db.QueryContext(ctx, `
SELECT id, username, COALESCE(name,''), token_prefix, COALESCE(used_count,0), created_at, last_used_at, revoked_at
  FROM sf_user_api_tokens
 WHERE username=$1
 ORDER BY created_at DESC
`, username)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []userAPITokenRecord
	for rows.Next() {
		var rec userAPITokenRecord
		if err := rows.Scan(&rec.ID, &rec.Username, &rec.Name, &rec.Prefix, &rec.UsedCount, &rec.CreatedAt, &rec.LastUsedAt, &rec.RevokedAt); err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func revokeUserAPIToken(ctx context.Context, db *sql.DB, username, tokenID string) error {
	if db == nil {
		return errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	username = strings.ToLower(strings.TrimSpace(username))
	tokenID = strings.TrimSpace(tokenID)
	if username == "" || tokenID == "" {
		return errs.B().Code(errs.InvalidArgument).Msg("username and tokenID required").Err()
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	res, err := db.ExecContext(ctx, `
UPDATE sf_user_api_tokens
   SET revoked_at=now()
 WHERE username=$1 AND id=$2 AND revoked_at IS NULL
`, username, tokenID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errs.B().Code(errs.NotFound).Msg("token not found").Err()
	}
	return nil
}

func lookupUserByAPIToken(ctx context.Context, db *sql.DB, token string) (username string, tokenID string, err error) {
	if db == nil {
		return "", "", errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return "", "", errs.B().Code(errs.Unauthenticated).Msg("missing token").Err()
	}
	sum := sha256.Sum256([]byte(token))

	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	var u string
	var id string
	err = db.QueryRowContext(ctx, `
SELECT username, id
  FROM sf_user_api_tokens
 WHERE token_hash=$1 AND revoked_at IS NULL
`, sum[:]).Scan(&u, &id)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", "", errs.B().Code(errs.Unauthenticated).Msg("invalid token").Err()
		}
		return "", "", err
	}

	// Best-effort usage tracking.
	_, _ = db.ExecContext(ctx, `
UPDATE sf_user_api_tokens
   SET last_used_at=now(),
       used_count=used_count+1
 WHERE id=$1
`, id)

	u = strings.ToLower(strings.TrimSpace(u))
	if u == "" {
		return "", "", fmt.Errorf("invalid token user")
	}
	return u, id, nil
}
