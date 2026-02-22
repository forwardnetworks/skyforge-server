package skyforge

// EveServerConfig is an internal, resolved view of an EVE-NG server configuration.
//
// This type is intentionally separate from the user/user-scope API types
// (UserEveServerConfig / UserScopeEveServerConfig) to keep resolver code simple.
//
// NOTE: EVE-NG execution is handled elsewhere; this type exists so Skyforge builds
// even when EVE-specific task runners are not compiled in.
type EveServerConfig struct {
	Name          string
	APIURL        string
	WebURL        string
	SkipTLSVerify bool

	APIUser     string
	APIPassword string

	SSHHost string
	SSHUser string
	SSHKey  string
}
