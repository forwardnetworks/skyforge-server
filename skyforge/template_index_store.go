package skyforge

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"
)

type templateIndexRecord struct {
	HeadSHA   string
	Templates []string
	UpdatedAt time.Time
}

func loadTemplateIndex(ctx context.Context, db *sql.DB, kind, owner, repo, branch, dir string) (*templateIndexRecord, error) {
	if db == nil {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	var (
		headSHA   string
		raw       []byte
		updatedAt time.Time
	)
	err := db.QueryRowContext(ctx, `
SELECT head_sha, templates, updated_at
FROM sf_template_indexes
WHERE kind=$1 AND owner=$2 AND repo=$3 AND branch=$4 AND dir=$5
`, kind, owner, repo, branch, dir).Scan(&headSHA, &raw, &updatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	out := &templateIndexRecord{
		HeadSHA:   headSHA,
		Templates: []string{},
		UpdatedAt: updatedAt,
	}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &out.Templates)
	}
	return out, nil
}

func upsertTemplateIndex(ctx context.Context, db *sql.DB, kind, owner, repo, branch, dir, headSHA string, templates []string) error {
	if db == nil {
		return nil
	}
	payload, err := json.Marshal(templates)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	_, err = db.ExecContext(ctx, `
INSERT INTO sf_template_indexes (kind, owner, repo, branch, dir, head_sha, templates)
VALUES ($1,$2,$3,$4,$5,$6,$7)
ON CONFLICT (kind, owner, repo, branch, dir) DO UPDATE
SET head_sha=excluded.head_sha,
    templates=excluded.templates,
    updated_at=now()
`, kind, owner, repo, branch, dir, headSHA, payload)
	return err
}
