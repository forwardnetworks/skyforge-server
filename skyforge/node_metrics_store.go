package skyforge

import (
	"context"
	"database/sql"
	"time"
)

type nodeMetricRow struct {
	Node      string
	Metric    string
	UpdatedAt time.Time
	RawJSON   string
}

func upsertNodeMetricSnapshot(ctx context.Context, db *sql.DB, node, metricName string, updatedAt time.Time, rawJSON string) error {
	if db == nil {
		return sql.ErrConnDone
	}
	_, err := db.ExecContext(ctx, `
INSERT INTO sf_node_metric_snapshots (node, metric_name, updated_at, metric_json)
VALUES ($1, $2, $3, $4::jsonb)
ON CONFLICT (node, metric_name)
DO UPDATE SET updated_at = EXCLUDED.updated_at, metric_json = EXCLUDED.metric_json
`, node, metricName, updatedAt.UTC(), rawJSON)
	return err
}

func listRecentNodeMetricSnapshots(ctx context.Context, db *sql.DB, since time.Duration, limit int) ([]nodeMetricRow, error) {
	if db == nil {
		return nil, sql.ErrConnDone
	}
	if limit <= 0 || limit > 5000 {
		limit = 2000
	}
	cutoff := time.Now().UTC().Add(-since)
	rows, err := db.QueryContext(ctx, `
SELECT node, metric_name, updated_at, metric_json::text
FROM sf_node_metric_snapshots
WHERE updated_at >= $1
ORDER BY node ASC, metric_name ASC
LIMIT $2
`, cutoff, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]nodeMetricRow, 0, 128)
	for rows.Next() {
		var r nodeMetricRow
		if err := rows.Scan(&r.Node, &r.Metric, &r.UpdatedAt, &r.RawJSON); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
