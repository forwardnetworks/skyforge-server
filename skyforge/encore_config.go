package skyforge

import (
	"encore.app/internal/skyforgeconfig"
	"encore.dev/config"
)

// skyforgeEncoreCfg provides access to the Encore-managed config defaults.
//
// The schema is defined in a shared internal package, but config.Load must be
// called from within a service package (per Encore rules).
var skyforgeEncoreCfg = config.Load[skyforgeconfig.EncoreConfig]()
