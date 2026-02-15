package skyforge

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

type forwardOnPremBackupS3Settings struct {
	Enabled       bool
	Bucket        string
	BucketPrefix  string
	Region        string
	Endpoint      string
	AccessKey     string
	SecretKey     string
	RetentionDays int
	UpdatedAt     time.Time
	UpdatedBy     string
}

type forwardOnPremBackupRunRow struct {
	ID          int64
	StartedAt   time.Time
	CompletedAt time.Time
	Status      string
	Actor       string
	DetailsJSON string
}

func getForwardOnPremBackupS3Settings(ctx context.Context, db *sql.DB, box *secretBox) (*forwardOnPremBackupS3Settings, error) {
	if db == nil {
		return nil, sql.ErrConnDone
	}
	if box == nil {
		return nil, errors.New("secret box unavailable")
	}
	var (
		enabled       bool
		bucket        string
		bucketPrefix  string
		region        string
		endpoint      string
		accessKeyEnc  string
		secretKeyEnc  string
		retentionDays int
		updatedAt     sql.NullTime
		updatedBy     sql.NullString
	)
	err := db.QueryRowContext(ctx, `
SELECT enabled,
       COALESCE(bucket,''),
       COALESCE(bucket_prefix,'forward/backups'),
       COALESCE(region,''),
       COALESCE(endpoint,''),
       COALESCE(access_key_enc,''),
       COALESCE(secret_key_enc,''),
       COALESCE(retention_days,30),
       updated_at,
       COALESCE(updated_by,'')
  FROM sf_forward_onprem_backup_s3_settings
 WHERE id='default'
`).Scan(
		&enabled,
		&bucket,
		&bucketPrefix,
		&region,
		&endpoint,
		&accessKeyEnc,
		&secretKeyEnc,
		&retentionDays,
		&updatedAt,
		&updatedBy,
	)
	if err != nil {
		if err == sql.ErrNoRows || isMissingDBRelation(err) {
			return nil, nil
		}
		return nil, err
	}
	accessKey := ""
	secretKey := ""
	if strings.TrimSpace(accessKeyEnc) != "" {
		if v, decErr := box.decrypt(accessKeyEnc); decErr == nil {
			accessKey = strings.TrimSpace(v)
		}
	}
	if strings.TrimSpace(secretKeyEnc) != "" {
		if v, decErr := box.decrypt(secretKeyEnc); decErr == nil {
			secretKey = strings.TrimSpace(v)
		}
	}
	out := &forwardOnPremBackupS3Settings{
		Enabled:       enabled,
		Bucket:        strings.TrimSpace(bucket),
		BucketPrefix:  strings.TrimSpace(bucketPrefix),
		Region:        strings.TrimSpace(region),
		Endpoint:      strings.TrimSpace(endpoint),
		AccessKey:     accessKey,
		SecretKey:     secretKey,
		RetentionDays: retentionDays,
		UpdatedBy:     strings.TrimSpace(updatedBy.String),
	}
	if out.BucketPrefix == "" {
		out.BucketPrefix = "forward/backups"
	}
	if out.RetentionDays <= 0 {
		out.RetentionDays = 30
	}
	if updatedAt.Valid {
		out.UpdatedAt = updatedAt.Time
	}
	return out, nil
}

func upsertForwardOnPremBackupS3Settings(ctx context.Context, db *sql.DB, box *secretBox, actor string, in forwardOnPremBackupS3Settings) error {
	if db == nil {
		return sql.ErrConnDone
	}
	if box == nil {
		return errors.New("secret box unavailable")
	}
	accessKeyEnc, err := encryptIfPlain(box, strings.TrimSpace(in.AccessKey))
	if err != nil {
		return err
	}
	secretKeyEnc, err := encryptIfPlain(box, strings.TrimSpace(in.SecretKey))
	if err != nil {
		return err
	}
	if in.RetentionDays <= 0 {
		in.RetentionDays = 30
	}
	if strings.TrimSpace(in.BucketPrefix) == "" {
		in.BucketPrefix = "forward/backups"
	}
	_, err = db.ExecContext(ctx, `
INSERT INTO sf_forward_onprem_backup_s3_settings (
  id,
  enabled,
  bucket,
  bucket_prefix,
  region,
  endpoint,
  access_key_enc,
  secret_key_enc,
  retention_days,
  updated_at,
  updated_by
) VALUES (
  'default',
  $1,
  $2,
  $3,
  $4,
  $5,
  $6,
  $7,
  $8,
  now(),
  NULLIF($9,'')
)
ON CONFLICT (id)
DO UPDATE SET
  enabled = EXCLUDED.enabled,
  bucket = EXCLUDED.bucket,
  bucket_prefix = EXCLUDED.bucket_prefix,
  region = EXCLUDED.region,
  endpoint = EXCLUDED.endpoint,
  access_key_enc = EXCLUDED.access_key_enc,
  secret_key_enc = EXCLUDED.secret_key_enc,
  retention_days = EXCLUDED.retention_days,
  updated_at = now(),
  updated_by = EXCLUDED.updated_by
`,
		in.Enabled,
		strings.TrimSpace(in.Bucket),
		strings.TrimSpace(in.BucketPrefix),
		strings.TrimSpace(in.Region),
		strings.TrimSpace(in.Endpoint),
		accessKeyEnc,
		secretKeyEnc,
		in.RetentionDays,
		strings.ToLower(strings.TrimSpace(actor)),
	)
	return err
}

func appendForwardOnPremBackupRun(ctx context.Context, db *sql.DB, status, actor string, details map[string]any) (int64, error) {
	if db == nil {
		return 0, sql.ErrConnDone
	}
	if details == nil {
		details = map[string]any{}
	}
	blob, err := json.Marshal(details)
	if err != nil {
		blob = []byte("{}")
	}
	var id int64
	err = db.QueryRowContext(ctx, `
INSERT INTO sf_forward_onprem_backup_runs (status, actor, details)
VALUES ($1, NULLIF($2,''), $3::jsonb)
RETURNING id
`, strings.TrimSpace(status), strings.ToLower(strings.TrimSpace(actor)), string(blob)).Scan(&id)
	return id, err
}

func completeForwardOnPremBackupRun(ctx context.Context, db *sql.DB, id int64, status string, details map[string]any) error {
	if db == nil {
		return sql.ErrConnDone
	}
	if id <= 0 {
		return nil
	}
	if details == nil {
		details = map[string]any{}
	}
	blob, err := json.Marshal(details)
	if err != nil {
		blob = []byte("{}")
	}
	_, err = db.ExecContext(ctx, `
UPDATE sf_forward_onprem_backup_runs
   SET completed_at = now(),
       status = $2,
       details = $3::jsonb
 WHERE id = $1
`, id, strings.TrimSpace(status), string(blob))
	return err
}

func listForwardOnPremBackupRuns(ctx context.Context, db *sql.DB, limit int) ([]forwardOnPremBackupRunRow, error) {
	if db == nil {
		return nil, sql.ErrConnDone
	}
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	rows, err := db.QueryContext(ctx, `
SELECT id, started_at, COALESCE(completed_at, started_at), COALESCE(status,''), COALESCE(actor,''), COALESCE(details::text,'{}')
  FROM sf_forward_onprem_backup_runs
 ORDER BY started_at DESC
 LIMIT $1
`, limit)
	if err != nil {
		if isMissingDBRelation(err) {
			return []forwardOnPremBackupRunRow{}, nil
		}
		return nil, err
	}
	defer rows.Close()
	out := make([]forwardOnPremBackupRunRow, 0, limit)
	for rows.Next() {
		var r forwardOnPremBackupRunRow
		if err := rows.Scan(&r.ID, &r.StartedAt, &r.CompletedAt, &r.Status, &r.Actor, &r.DetailsJSON); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
