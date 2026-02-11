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
var nosPerfProfilesByNormalizedKind = func() map[string]nosResourceProfile {
	out := map[string]nosResourceProfile{}
	for k, v := range nosPerfProfilesByKind {
		nk := normalizeNOSProfileKey(k)
		if nk == "" {
			continue
		}
		if _, exists := out[nk]; !exists {
			out[nk] = v
		}
	}
	return out
}()

var nosKindProfileAliases = map[string]string{
	"arubacx":       "aruba_arubaos-cx",
	"asav":          "cisco_asav",
	"dellos10":      "vr-ftosv",
	"fortios":       "vr-fortios",
	"iol":           "cisco_iol",
	"ioll2":         "cisco_iol_l2",
	"iosv":          "cisco_vios",
	"iosvl2":        "cisco_viosl2",
	"nxos":          "vr-n9kv",
	"sros":          "vr-sros",
	"vjunos-router": "juniper_vjunosrouter",
	"vjunos-switch": "juniper_vjunosswitch",
	"vmx":           "vr-vmx",
	"vptx":          "juniper_vjunosevolved",
}

func nosResourceProfileForKind(kind string) (nosResourceProfile, bool) {
	kind = strings.ToLower(strings.TrimSpace(kind))
	if kind == "" {
		return nosResourceProfile{}, false
	}
	p, ok := nosPerfProfilesByKind[kind]
	if ok {
		return p, true
	}
	p, ok = nosPerfProfilesByNormalizedKind[normalizeNOSProfileKey(kind)]
	return p, ok
}

func normalizeNOSProfileKey(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') {
			b.WriteByte(ch)
		}
	}
	return b.String()
}

func containerImageBaseName(image string) string {
	image = strings.TrimSpace(image)
	if image == "" {
		return ""
	}
	if at := strings.Index(image, "@"); at > 0 {
		image = image[:at]
	}
	slash := strings.LastIndex(image, "/")
	colon := strings.LastIndex(image, ":")
	if colon > slash {
		image = image[:colon]
	}
	if slash >= 0 && slash+1 < len(image) {
		image = image[slash+1:]
	}
	return strings.ToLower(strings.TrimSpace(image))
}

func nosResourceProfileForNode(kind string, image string) (nosResourceProfile, string, bool) {
	kind = strings.ToLower(strings.TrimSpace(kind))
	imageBase := containerImageBaseName(image)

	candidates := make([]string, 0, 4)
	if kind != "" {
		candidates = append(candidates, kind)
		if alias, ok := nosKindProfileAliases[kind]; ok {
			candidates = append(candidates, alias)
		}
	}
	if imageBase != "" {
		candidates = append(candidates, imageBase)
	}

	seen := map[string]struct{}{}
	for _, c := range candidates {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if _, ok := seen[c]; ok {
			continue
		}
		seen[c] = struct{}{}
		if p, ok := nosResourceProfileForKind(c); ok {
			return p, c, true
		}
	}
	return nosResourceProfile{}, "", false
}
