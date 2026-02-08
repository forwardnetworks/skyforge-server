package skyforge

import (
	"os"

	"encore.app/internal/skyforgeconfig"
	"encore.dev/config"
)

// skyforgeEncoreCfg provides access to the Encore-managed config defaults.
//
// The schema is defined in a shared internal package, but config.Load must be
// called from within a service package (per Encore rules).
var skyforgeEncoreCfg = func() skyforgeconfig.EncoreConfig {
	// In plain `go test` the Encore SDK stubs panic. Avoid that by using defaults.
	if os.Getenv("ENCORE_CFG") == "" {
		return skyforgeconfig.EncoreConfig{}
	}
	return config.Load[skyforgeconfig.EncoreConfig]()
}()
