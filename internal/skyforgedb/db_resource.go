package skyforgedb

import "encore.dev/storage/sqldb"

// SkyforgeDB is the shared Postgres database for Skyforge services (API + worker).
//
// The resource name must match the key in infra.config.json ("skyforge_server").
var SkyforgeDB = sqldb.NewDatabase("skyforge_server", sqldb.DatabaseConfig{
	Migrations: "./migrations",
})

