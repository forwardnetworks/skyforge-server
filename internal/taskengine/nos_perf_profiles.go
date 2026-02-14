package taskengine

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
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
	"cat8000v":      "cisco_c8000v",
	"csr":           "vr-csr",
	"cumulus":       "cumulus",
	"dellos10":      "vr-ftosv",
	"eos":           "eos",
	"exos":          "extreme_exos",
	"fortios":       "vr-fortios",
	"iol":           "cisco_iol",
	"ioll2":         "cisco_iol_l2",
	"ios":           "cisco_vios",
	"iosv":          "cisco_vios",
	"iosvl2":        "cisco_viosl2",
	"linux":         "linux",
	"nxos":          "vr-n9kv",
	"sros":          "vr-sros",
	"vsrx":          "juniper_vsrx",
	"vjunos-router": "juniper_vjunosrouter",
	"vjunos-switch": "juniper_vjunosswitch",
	"vmx":           "vr-vmx",
	"vptx":          "juniper_vjunosevolved",
}

type clabernetesResourceFallbackMode string

const (
	clabernetesResourceFallbackConservative clabernetesResourceFallbackMode = "conservative"
	clabernetesResourceFallbackNone         clabernetesResourceFallbackMode = "none"
	clabernetesResourceFallbackFail         clabernetesResourceFallbackMode = "fail"
)

const (
	defaultClabernetesFallbackCPURequest    = "500m"
	defaultClabernetesFallbackMemoryRequest = "1Gi"
)

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

func clabernetesResourceFallbackModeFromEnv(env map[string]string) clabernetesResourceFallbackMode {
	switch strings.ToLower(strings.TrimSpace(envString(env, "SKYFORGE_CLABERNETES_RESOURCE_FALLBACK"))) {
	case "", string(clabernetesResourceFallbackConservative):
		return clabernetesResourceFallbackConservative
	case string(clabernetesResourceFallbackNone):
		return clabernetesResourceFallbackNone
	case string(clabernetesResourceFallbackFail):
		return clabernetesResourceFallbackFail
	default:
		return clabernetesResourceFallbackConservative
	}
}

func clabernetesFallbackResourceProfileFromEnv(env map[string]string) nosResourceProfile {
	cpu := strings.TrimSpace(envString(env, "SKYFORGE_CLABERNETES_FALLBACK_CPU_REQUEST"))
	if cpu == "" {
		cpu = defaultClabernetesFallbackCPURequest
	}
	mem := strings.TrimSpace(envString(env, "SKYFORGE_CLABERNETES_FALLBACK_MEMORY_REQUEST"))
	if mem == "" {
		mem = defaultClabernetesFallbackMemoryRequest
	}
	return nosResourceProfile{
		CPURequest:    cpu,
		MemoryRequest: mem,
	}
}

type nosResourceAssignmentResult struct {
	Mode           clabernetesResourceFallbackMode
	Resources      map[string]any
	MatchedByNode  map[string]string
	FallbackByNode map[string]string
	Unresolved     map[string]string
}

func buildNOSResourceAssignments(nodeSpecs map[string]containerlabNodeSpec, env map[string]string, enableLimits bool) (nosResourceAssignmentResult, error) {
	result := nosResourceAssignmentResult{
		Mode:           clabernetesResourceFallbackModeFromEnv(env),
		Resources:      map[string]any{},
		MatchedByNode:  map[string]string{},
		FallbackByNode: map[string]string{},
		Unresolved:     map[string]string{},
	}

	fallbackProfile := clabernetesFallbackResourceProfileFromEnv(env)
	for nodeName, nodeSpec := range nodeSpecs {
		nodeName = strings.TrimSpace(nodeName)
		if nodeName == "" {
			continue
		}
		profile, matchedBy, ok := nosResourceProfileForNode(nodeSpec.Kind, nodeSpec.Image)
		if !ok {
			desc := fmt.Sprintf("kind=%q image=%q", strings.TrimSpace(nodeSpec.Kind), strings.TrimSpace(nodeSpec.Image))
			result.Unresolved[nodeName] = desc
			switch result.Mode {
			case clabernetesResourceFallbackNone:
				continue
			case clabernetesResourceFallbackFail:
				continue
			default:
				profile = fallbackProfile
				matchedBy = "fallback-conservative"
				result.FallbackByNode[nodeName] = desc
			}
		}

		req := map[string]any{}
		if strings.TrimSpace(profile.CPURequest) != "" {
			req["cpu"] = strings.TrimSpace(profile.CPURequest)
		}
		if strings.TrimSpace(profile.MemoryRequest) != "" {
			req["memory"] = strings.TrimSpace(profile.MemoryRequest)
		}

		rr := map[string]any{}
		if len(req) > 0 {
			rr["requests"] = req
		}
		if enableLimits {
			lim := map[string]any{}
			if strings.TrimSpace(profile.CPULimit) != "" {
				lim["cpu"] = strings.TrimSpace(profile.CPULimit)
			}
			if strings.TrimSpace(profile.MemoryLimit) != "" {
				lim["memory"] = strings.TrimSpace(profile.MemoryLimit)
			}
			if len(lim) > 0 {
				rr["limits"] = lim
			}
		}
		if len(rr) == 0 {
			continue
		}
		result.Resources[nodeName] = rr
		result.MatchedByNode[nodeName] = matchedBy
	}

	if result.Mode == clabernetesResourceFallbackFail && len(result.Unresolved) > 0 {
		return result, fmt.Errorf(
			"clabernetes resources: missing profiles for nodes: %s (set SKYFORGE_CLABERNETES_RESOURCE_FALLBACK=conservative|none)",
			formatNodeDetails(result.Unresolved),
		)
	}
	return result, nil
}

func formatNodeDetails(m map[string]string) string {
	if len(m) == 0 {
		return ""
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s(%s)", k, m[k]))
	}
	return strings.Join(parts, ", ")
}
