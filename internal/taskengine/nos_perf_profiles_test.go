package taskengine

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestNOSResourceProfileForNode(t *testing.T) {
	p, matchedBy, ok := nosResourceProfileForNode("nxos", "ghcr.io/forwardnetworks/vrnetlab/vr-n9kv:9.3.8")
	if !ok {
		t.Fatalf("expected nxos profile match")
	}
	if p.CPURequest != "4000m" || p.MemoryRequest != "12Gi" {
		t.Fatalf("unexpected nxos profile: %+v", p)
	}
	if matchedBy == "" {
		t.Fatalf("expected non-empty matchedBy")
	}
}

func TestNOSResourceProfileNormalization(t *testing.T) {
	p, ok := nosResourceProfileForKind("juniper_vjunos-router")
	if !ok {
		t.Fatalf("expected normalized match for juniper_vjunos-router")
	}
	if p.CPURequest != "4000m" || p.MemoryRequest != "6Gi" {
		t.Fatalf("unexpected vjunos-router profile: %+v", p)
	}
}

func TestContainerImageBaseName(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{in: "ghcr.io/forwardnetworks/vrnetlab/vr-n9kv:9.3.8", want: "vr-n9kv"},
		{in: "ghcr.io/forwardnetworks/vrnetlab/cisco_vios@sha256:deadbeef", want: "cisco_vios"},
		{in: "vrnetlab/cisco_asav:9-16-4-57", want: "cisco_asav"},
	}
	for _, tc := range cases {
		if got := containerImageBaseName(tc.in); got != tc.want {
			t.Fatalf("containerImageBaseName(%q): got=%q want=%q", tc.in, got, tc.want)
		}
	}
}

func TestClabernetesResourceFallbackModeFromEnv(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		want clabernetesResourceFallbackMode
	}{
		{
			name: "default conservative",
			env:  map[string]string{},
			want: clabernetesResourceFallbackConservative,
		},
		{
			name: "explicit none",
			env: map[string]string{
				"SKYFORGE_CLABERNETES_RESOURCE_FALLBACK": "none",
			},
			want: clabernetesResourceFallbackNone,
		},
		{
			name: "explicit fail",
			env: map[string]string{
				"SKYFORGE_CLABERNETES_RESOURCE_FALLBACK": "fail",
			},
			want: clabernetesResourceFallbackFail,
		},
		{
			name: "invalid fallback defaults to conservative",
			env: map[string]string{
				"SKYFORGE_CLABERNETES_RESOURCE_FALLBACK": "invalid",
			},
			want: clabernetesResourceFallbackConservative,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := clabernetesResourceFallbackModeFromEnv(tc.env); got != tc.want {
				t.Fatalf("clabernetesResourceFallbackModeFromEnv: got=%q want=%q", got, tc.want)
			}
		})
	}
}

func TestBuildNOSResourceAssignmentsConservativeFallback(t *testing.T) {
	specs := map[string]containerlabNodeSpec{
		"r1": {Kind: "nxos", Image: "ghcr.io/forwardnetworks/vrnetlab/vr-n9kv:9.3.8"},
		"r2": {Kind: "unknown", Image: "ghcr.io/example/vendor/mystery:1.2"},
	}
	result, err := buildNOSResourceAssignments(specs, map[string]string{}, false)
	if err != nil {
		t.Fatalf("buildNOSResourceAssignments error: %v", err)
	}
	if len(result.Resources) != 2 {
		t.Fatalf("resources count: got=%d want=2", len(result.Resources))
	}
	if result.MatchedByNode["r1"] != "vr-n9kv" {
		t.Fatalf("r1 matchedBy: got=%q want=%q", result.MatchedByNode["r1"], "vr-n9kv")
	}
	if result.MatchedByNode["r2"] != "fallback-conservative" {
		t.Fatalf("r2 matchedBy: got=%q want=%q", result.MatchedByNode["r2"], "fallback-conservative")
	}
	if _, ok := result.FallbackByNode["r2"]; !ok {
		t.Fatalf("expected r2 fallback details")
	}
}

func TestBuildNOSResourceAssignmentsNoneFallback(t *testing.T) {
	specs := map[string]containerlabNodeSpec{
		"r1": {Kind: "nxos", Image: "ghcr.io/forwardnetworks/vrnetlab/vr-n9kv:9.3.8"},
		"r2": {Kind: "unknown", Image: "ghcr.io/example/vendor/mystery:1.2"},
	}
	result, err := buildNOSResourceAssignments(specs, map[string]string{
		"SKYFORGE_CLABERNETES_RESOURCE_FALLBACK": "none",
	}, false)
	if err != nil {
		t.Fatalf("buildNOSResourceAssignments error: %v", err)
	}
	if len(result.Resources) != 1 {
		t.Fatalf("resources count: got=%d want=1", len(result.Resources))
	}
	if _, ok := result.Resources["r2"]; ok {
		t.Fatalf("r2 should be skipped when fallback=none")
	}
	if _, ok := result.Unresolved["r2"]; !ok {
		t.Fatalf("expected r2 in unresolved when fallback=none")
	}
}

func TestBuildNOSResourceAssignmentsFailFallback(t *testing.T) {
	specs := map[string]containerlabNodeSpec{
		"r1": {Kind: "nxos", Image: "ghcr.io/forwardnetworks/vrnetlab/vr-n9kv:9.3.8"},
		"r2": {Kind: "unknown", Image: "ghcr.io/example/vendor/mystery:1.2"},
	}
	_, err := buildNOSResourceAssignments(specs, map[string]string{
		"SKYFORGE_CLABERNETES_RESOURCE_FALLBACK": "fail",
	}, false)
	if err == nil {
		t.Fatalf("expected error when fallback=fail and unknown profile exists")
	}
}

func TestBuildNOSResourceAssignmentsCustomFallbackValues(t *testing.T) {
	specs := map[string]containerlabNodeSpec{
		"r1": {Kind: "unknown", Image: "ghcr.io/example/vendor/mystery:1.2"},
	}
	result, err := buildNOSResourceAssignments(specs, map[string]string{
		"SKYFORGE_CLABERNETES_FALLBACK_CPU_REQUEST":    "750m",
		"SKYFORGE_CLABERNETES_FALLBACK_MEMORY_REQUEST": "1536Mi",
	}, false)
	if err != nil {
		t.Fatalf("buildNOSResourceAssignments error: %v", err)
	}
	rr, ok := result.Resources["r1"].(map[string]any)
	if !ok {
		t.Fatalf("r1 resources missing")
	}
	req, ok := rr["requests"].(map[string]any)
	if !ok {
		t.Fatalf("r1 requests missing")
	}
	if req["cpu"] != "750m" || req["memory"] != "1536Mi" {
		t.Fatalf("unexpected fallback requests: %+v", req)
	}
}

func TestNOSProfilesCoverNetlabDefaultImages(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("runtime.Caller failed")
	}
	defaultsPath := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", "..", "images", "netlab-generator", "defaults.yml"))
	raw, err := os.ReadFile(defaultsPath)
	if err != nil {
		t.Fatalf("read defaults.yml (%s): %v", defaultsPath, err)
	}
	var doc struct {
		Devices map[string]struct {
			Clab struct {
				Image string `yaml:"image"`
			} `yaml:"clab"`
		} `yaml:"devices"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse defaults.yml: %v", err)
	}
	missing := []string{}
	for device, cfg := range doc.Devices {
		image := strings.TrimSpace(cfg.Clab.Image)
		if image == "" {
			continue
		}
		if _, _, ok := nosResourceProfileForNode(device, image); !ok {
			missing = append(missing, fmt.Sprintf("%s(%s)", device, containerImageBaseName(image)))
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("missing resource profiles for defaults.yml images: %s", strings.Join(missing, ", "))
	}
}
