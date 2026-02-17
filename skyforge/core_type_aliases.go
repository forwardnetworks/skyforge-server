package skyforge

import "encore.app/internal/skyforgecore"

// Re-export core configuration types from the non-service library package so the
// skyforge service can continue to refer to them without a large refactor.
//
// This is a stepping stone towards a "true service split" where the worker
// service does not import the skyforge service package at all.
type (
	Config             = skyforgecore.Config
	ElasticConfig      = skyforgecore.ElasticConfig
	OIDCConfig         = skyforgecore.OIDCConfig
	LDAPConfig         = skyforgecore.LDAPConfig
	UIConfig           = skyforgecore.UIConfig
	NetlabConfig       = skyforgecore.NetlabConfig
	NetlabServerConfig = skyforgecore.NetlabServerConfig
	WorkspacesConfig   = skyforgecore.UserContextsConfig
)
