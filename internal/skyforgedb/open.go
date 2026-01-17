package skyforgedb

import (
	"context"
	"database/sql"
	"time"

	"encore.app/internal/db"
	"encore.dev/storage/sqldb"
)

func Open(ctx context.Context, database *sqldb.Database) (*sql.DB, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if database == nil {
		return nil, nil
	}
	stdlib, err := db.OpenStdlibWithRetry(ctx, database, 10, 250*time.Millisecond)
	if err != nil {
		return nil, err
	}
	stdlib.SetMaxOpenConns(8)
	stdlib.SetMaxIdleConns(4)
	stdlib.SetConnMaxLifetime(30 * time.Minute)
	return stdlib, nil
}
