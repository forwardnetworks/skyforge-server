package skyforge

import (
	"context"
	"database/sql"
	"time"

	dbutil "encore.app/internal/db"
	_ "encore.app/internal/secrets"
	"encore.dev/storage/sqldb"
)

var skyforgeDB = sqldb.NewDatabase("skyforge_server", sqldb.DatabaseConfig{
	Migrations: "./migrations",
})

func openSkyforgeEncoreDB(ctx context.Context) (*sql.DB, error) {
	if err := dbutil.WaitForDB(ctx, skyforgeDB, 20, 2*time.Second); err != nil {
		return nil, err
	}
	stdlib, err := dbutil.OpenStdlibWithRetry(ctx, skyforgeDB, 20, 2*time.Second)
	if err != nil {
		return nil, err
	}
	stdlib.SetMaxOpenConns(8)
	stdlib.SetMaxIdleConns(4)
	stdlib.SetConnMaxLifetime(30 * time.Minute)
	return stdlib, nil
}

