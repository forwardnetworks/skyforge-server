package skyforgedb

import (
	"os"

	"encore.dev/storage/sqldb"
)

// SkyforgeDB is the shared Postgres database for Skyforge services (API + worker).
//
// The resource name must match the key in infra.config.json ("skyforge_server").
var SkyforgeDB = newDatabase("skyforge_server", sqldb.DatabaseConfig{Migrations: "./migrations"})

func newDatabase(name string, cfg sqldb.DatabaseConfig) *sqldb.Database {
	// In plain `go test` the Encore SDK stubs panic. Avoid that by returning nil.
	if os.Getenv("ENCORE_CFG") == "" {
		return nil
	}
	return sqldb.NewDatabase(name, cfg)
}
