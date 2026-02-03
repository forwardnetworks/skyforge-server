package taskengine

import (
	_ "embed"
	"encoding/json"
	"strings"
)

//go:embed nos_perf_profiles.json
var nosPerfProfilesJSON []byte

type nosPerfProfilesFile struct {
	ProfilesByKind map[string]nosResourceProfile `json:"profilesByKind"`
}

type nosResourceProfile struct {
	CPURequest    string `json:"cpuRequest,omitempty"`
	CPULimit      string `json:"cpuLimit,omitempty"`
	MemoryRequest string `json:"memoryRequest,omitempty"`
	MemoryLimit   string `json:"memoryLimit,omitempty"`
}

func loadNOSPerfProfiles() map[string]nosResourceProfile {
	out := map[string]nosResourceProfile{}
	if len(nosPerfProfilesJSON) == 0 {
		return out
	}
	var f nosPerfProfilesFile
	if err := json.Unmarshal(nosPerfProfilesJSON, &f); err != nil {
		return out
	}
	for k, v := range f.ProfilesByKind {
		key := strings.ToLower(strings.TrimSpace(k))
		if key == "" {
			continue
		}
		out[key] = v
	}
	return out
}

var nosPerfProfilesByKind = loadNOSPerfProfiles()

func nosResourceProfileForKind(kind string) (nosResourceProfile, bool) {
	kind = strings.ToLower(strings.TrimSpace(kind))
	if kind == "" {
		return nosResourceProfile{}, false
	}
	p, ok := nosPerfProfilesByKind[kind]
	return p, ok
}

