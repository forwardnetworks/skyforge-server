package taskengine

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestCombineNetlabSnippets_OrderAndExtras(t *testing.T) {
	data := map[string]string{
		"bgp":                "bgp\n",
		"firewall.zonebased": "zbf\n",
		"initial":            "init\n",
		"zzz":                "extra\n",
	}
	known := []string{"initial", "bgp", "firewall.zonebased"}

	got := combineNetlabSnippets(data, known)
	want := "init\nbgp\nzbf\nextra\n"
	if got != want {
		t.Fatalf("combined mismatch:\nwant:\n%q\ngot:\n%q", want, got)
	}
}

func TestUpsertC9sMount_ReplacesByFilePath(t *testing.T) {
	existing := []c9sFileFromConfigMap{
		{ConfigMapName: "a", ConfigMapPath: "x", FilePath: "/config/startup-config.cfg", Mode: "read"},
	}
	out := upsertC9sMount(existing, c9sFileFromConfigMap{ConfigMapName: "b", ConfigMapPath: "y", FilePath: "/config/startup-config.cfg", Mode: "read"})
	if len(out) != 1 {
		t.Fatalf("expected 1 mount, got %d", len(out))
	}
	if out[0].ConfigMapName != "b" || out[0].ConfigMapPath != "y" {
		t.Fatalf("mount not replaced: %+v", out[0])
	}
}

func TestExtractNetlabConfigModeOverrides(t *testing.T) {
	in := []string{
		"defaults.devices.eos.clab.group_vars.netlab_config_mode=sh",
		"defaults.devices.ios.clab.group_vars.netlab_config_mode = startup",
		"defaults.devices.junos.clab.group_vars.netlab_config_mode=\"startup\"",
		"devices.arubacx.clab.group_vars.netlab_config_mode=startup",  // legacy path still accepted
		"defaults.devices.nxos.group_vars.netlab_config_mode=startup", // wrong path
		"defaults.devices.eos.clab.group_vars.ansible_user=admin",     // wrong key
		"garbage",
	}
	got := extractNetlabConfigModeOverrides(in)
	if got["eos"] != "sh" {
		t.Fatalf("expected eos=sh, got %#v", got["eos"])
	}
	if got["ios"] != "startup" {
		t.Fatalf("expected ios=startup, got %#v", got["ios"])
	}
	if got["junos"] != "startup" {
		t.Fatalf("expected junos=startup, got %#v", got["junos"])
	}
	if got["arubacx"] != "startup" {
		t.Fatalf("expected arubacx=startup from legacy key, got %#v", got["arubacx"])
	}
	if _, ok := got["nxos"]; ok {
		t.Fatalf("did not expect nxos entry, got %#v", got)
	}
}

func TestShouldUseNativeNetlabConfigModeForNode(t *testing.T) {
	opts := netlabC9sStartupConfigOptions{
		NativeConfigModesEnabled: true,
		DeviceConfigMode: map[string]string{
			"eos":      "sh",
			"ios":      "startup",
			"junos":    "startup",
			"dellos10": "startup",
		},
	}

	if !shouldUseNativeNetlabConfigModeForNode("ceos", "ghcr.io/forwardnetworks/ceos:4.34.2F", opts) {
		t.Fatalf("expected ceos/eos node to use native config mode")
	}
	if !shouldUseNativeNetlabConfigModeForNode("cisco_iol", "ghcr.io/forwardnetworks/vrnetlab/cisco_iol:17.16.01a", opts) {
		t.Fatalf("expected iol node to inherit ios startup mode")
	}
	if !shouldUseNativeNetlabConfigModeForNode("vr-vmx", "ghcr.io/forwardnetworks/vrnetlab/vr-vmx:18.2R1.9", opts) {
		t.Fatalf("expected vmx node to inherit junos startup mode")
	}
	if shouldUseNativeNetlabConfigModeForNode("nxos", "ghcr.io/forwardnetworks/vrnetlab/vr-n9kv:9.3.8-skyforge1", opts) {
		t.Fatalf("did not expect nxos node to use native config mode by default")
	}

	opts.NativeConfigModesEnabled = false
	if shouldUseNativeNetlabConfigModeForNode("ceos", "ghcr.io/forwardnetworks/ceos:4.34.2F", opts) {
		t.Fatalf("did not expect native mode when globally disabled")
	}
}

func TestEffectiveNetlabConfigModeByDevice_DefaultsAndOverrides(t *testing.T) {
	got := effectiveNetlabConfigModeByDevice([]string{
		"defaults.devices.eos.clab.group_vars.netlab_config_mode=startup",
		"defaults.devices.nxos.clab.group_vars.netlab_config_mode=startup",
	})
	if got["eos"] != "startup" {
		t.Fatalf("expected eos override to startup, got %#v", got["eos"])
	}
	if got["frr"] != "sh" {
		t.Fatalf("expected frr default sh, got %#v", got["frr"])
	}
	if got["ios"] != "startup" {
		t.Fatalf("expected ios default startup, got %#v", got["ios"])
	}
	if got["nxos"] != "startup" {
		t.Fatalf("expected nxos override startup, got %#v", got["nxos"])
	}
}

func TestNetlabDeviceKeyForClabNode_JunosKindAliases(t *testing.T) {
	cases := []struct {
		kind string
		want string
	}{
		{kind: "juniper_vmx", want: "vmx"},
		{kind: "juniper_vsrx", want: "vsrx"},
		{kind: "juniper_vjunosevolved", want: "vptx"},
		{kind: "juniper_vjunosrouter", want: "vjunos-router"},
		{kind: "juniper_vjunosswitch", want: "vjunos-switch"},
	}
	for _, tc := range cases {
		if got := netlabDeviceKeyForClabNode(tc.kind, ""); got != tc.want {
			t.Fatalf("kind alias mismatch kind=%q got=%q want=%q", tc.kind, got, tc.want)
		}
	}
}

func TestResolveNetlabConfigModeForDevice_PreferenceAndFallback(t *testing.T) {
	defaults := map[string]string{
		"eos": "sh",
		"ios": "startup",
	}
	overrides := map[string]string{
		"eos": "ansible",
	}

	mode, source, valid := resolveNetlabConfigModeForDevice("ceos", defaults, overrides)
	if !valid || mode != "ansible" || source != "override" {
		t.Fatalf("expected ceos override ansible, got mode=%q source=%q valid=%v", mode, source, valid)
	}

	mode, source, valid = resolveNetlabConfigModeForDevice("ioll2", defaults, nil)
	if !valid || mode != "startup" || source != "defaults" {
		t.Fatalf("expected ioll2 defaults startup, got mode=%q source=%q valid=%v", mode, source, valid)
	}

	mode, source, valid = resolveNetlabConfigModeForDevice("nxos", defaults, nil)
	if !valid || mode != "ansible" || source != "fallback" {
		t.Fatalf("expected nxos fallback ansible, got mode=%q source=%q valid=%v", mode, source, valid)
	}
}

func TestDefaultNetlabConfigModesByDeviceCatalog_MatchesGeneratorDefaultsYAML(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("runtime.Caller failed")
	}
	defaultsPath := filepath.Join(filepath.Dir(thisFile), "..", "..", "images", "netlab-generator", "defaults.yml")
	data, err := os.ReadFile(defaultsPath)
	if err != nil {
		t.Fatalf("read defaults.yml failed: %v", err)
	}

	var doc map[string]any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parse defaults.yml failed: %v", err)
	}

	asMap := func(raw any) map[string]any {
		if raw == nil {
			return map[string]any{}
		}
		if m, ok := raw.(map[string]any); ok {
			return m
		}
		return map[string]any{}
	}

	want := map[string]string{}
	devices := asMap(doc["devices"])
	for device, raw := range devices {
		dev := strings.ToLower(strings.TrimSpace(device))
		if dev == "" {
			continue
		}
		cfg := asMap(raw)
		clab := asMap(cfg["clab"])
		groupVars := asMap(clab["group_vars"])
		mode := strings.ToLower(strings.TrimSpace(asString(groupVars["netlab_config_mode"])))
		if mode == "" {
			continue
		}
		want[dev] = mode
	}

	got := defaultNetlabConfigModesByDevice()
	if len(got) != len(want) {
		t.Fatalf("defaults mode size mismatch: got=%d want=%d got=%#v want=%#v", len(got), len(want), got, want)
	}
	for k, w := range want {
		g, ok := got[k]
		if !ok {
			t.Fatalf("missing defaults mode for %q", k)
		}
		if g != w {
			t.Fatalf("defaults mode mismatch for %q: got=%q want=%q", k, g, w)
		}
	}
}

func asString(v any) string {
	switch vv := v.(type) {
	case string:
		return strings.TrimSpace(vv)
	default:
		return ""
	}
}
