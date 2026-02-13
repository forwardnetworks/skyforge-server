package taskengine

import (
	"fmt"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func parseYAMLMap(t *testing.T, in []byte) map[string]any {
	t.Helper()
	var out map[string]any
	if err := yaml.Unmarshal(in, &out); err != nil {
		t.Fatalf("unmarshal yaml: %v", err)
	}
	if out == nil {
		out = map[string]any{}
	}
	return out
}

func getMap(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	if m, ok := v.(map[any]any); ok {
		out := make(map[string]any, len(m))
		for k, val := range m {
			key := strings.TrimSpace(fmt.Sprintf("%v", k))
			if key == "" {
				continue
			}
			out[key] = val
		}
		return out
	}
	return map[string]any{}
}

func listContainsString(v any, want string) bool {
	want = strings.TrimSpace(want)
	switch vv := v.(type) {
	case string:
		return strings.TrimSpace(vv) == want
	case []any:
		for _, item := range vv {
			if strings.TrimSpace(fmt.Sprintf("%v", item)) == want {
				return true
			}
		}
	case []string:
		for _, item := range vv {
			if strings.TrimSpace(item) == want {
				return true
			}
		}
	}
	return false
}

func countStringInList(v any, want string) int {
	want = strings.TrimSpace(want)
	count := 0
	switch vv := v.(type) {
	case string:
		if strings.TrimSpace(vv) == want {
			return 1
		}
	case []any:
		for _, item := range vv {
			if strings.TrimSpace(fmt.Sprintf("%v", item)) == want {
				count++
			}
		}
	case []string:
		for _, item := range vv {
			if strings.TrimSpace(item) == want {
				count++
			}
		}
	}
	return count
}

func TestPatchNetlabTopologyYAMLForSnmp_InsertsGeneratedConfiglets(t *testing.T) {
	src := []byte(`
name: test
defaults:
  device: eos
nodes:
  r1:
    device: iol
  h1:
    device: linux
  r2: {}
`)

	out, err := patchNetlabTopologyYAMLForSnmp(src, "token-abc", "10.0.0.10", 162)
	if err != nil {
		t.Fatalf("patch failed: %v", err)
	}
	topo := parseYAMLMap(t, out)

	if !listContainsString(topo["plugin"], "files") {
		t.Fatalf("expected plugin list to include files, got %#v", topo["plugin"])
	}

	groups := getMap(topo["groups"])
	all := getMap(groups["all"])
	if listContainsString(all["config"], "snmp_config") {
		t.Fatalf("expected groups.all.config to exclude snmp_config, got %#v", all["config"])
	}
	eos := getMap(groups["eos"])
	if !listContainsString(eos["config"], "skyforge_eos_auth") {
		t.Fatalf("expected groups.eos.config to include skyforge_eos_auth, got %#v", eos["config"])
	}

	nodes := getMap(topo["nodes"])
	r1 := getMap(nodes["r1"])
	h1 := getMap(nodes["h1"])
	r2 := getMap(nodes["r2"])
	if !listContainsString(r1["config"], "snmp_config") {
		t.Fatalf("expected non-linux node r1 to include snmp_config, got %#v", r1["config"])
	}
	if listContainsString(h1["config"], "snmp_config") {
		t.Fatalf("expected linux node h1 to exclude snmp_config, got %#v", h1["config"])
	}
	if !listContainsString(r2["config"], "snmp_config") {
		t.Fatalf("expected default-device node r2 to include snmp_config, got %#v", r2["config"])
	}

	defaults := getMap(topo["defaults"])
	snmp := getMap(defaults["snmp"])
	if got := strings.TrimSpace(fmt.Sprintf("%v", snmp["community"])); got != "token-abc" {
		t.Fatalf("expected defaults.snmp.community token-abc, got %q", got)
	}
	if got := strings.TrimSpace(fmt.Sprintf("%v", snmp["trap_host"])); got != "10.0.0.10" {
		t.Fatalf("expected defaults.snmp.trap_host 10.0.0.10, got %q", got)
	}
	if got := strings.TrimSpace(fmt.Sprintf("%v", snmp["trap_port"])); got != "162" {
		t.Fatalf("expected defaults.snmp.trap_port 162, got %q", got)
	}

	configlets := getMap(topo["configlets"])
	snmpCfg := getMap(configlets["snmp_config"])
	if len(snmpCfg) == 0 {
		t.Fatalf("expected generated configlets.snmp_config to be non-empty (configlets=%#v topo=%#v)", configlets, topo)
	}
	if got := strings.TrimSpace(fmt.Sprintf("%v", snmpCfg["iol"])); got == "" {
		t.Fatalf("expected generated iol snmp_config template")
	}
	if _, ok := snmpCfg["linux"]; ok {
		t.Fatalf("expected linux snmp_config template to be absent")
	}
	eosAuth := getMap(configlets["skyforge_eos_auth"])
	if got := strings.TrimSpace(fmt.Sprintf("%v", eosAuth["eos"])); got == "" {
		t.Fatalf("expected generated eos auth template")
	}
}

func TestPatchNetlabTopologyYAMLForSnmp_NoDupesAndPreservesExistingTemplate(t *testing.T) {
	src := []byte(`
name: test
plugin: [files]
groups:
  all:
    config: [initial, snmp_config]
  eos:
    config: [initial, skyforge_eos_auth]
configlets:
  snmp_config:
    iol: "custom-iol-template"
  skyforge_eos_auth:
    eos: "custom-eos-auth"
nodes:
  r1:
    device: iol
  h1:
    device: linux
`)

	out, err := patchNetlabTopologyYAMLForSnmp(src, "token-xyz", "", 0)
	if err != nil {
		t.Fatalf("patch failed: %v", err)
	}
	topo := parseYAMLMap(t, out)

	if got := countStringInList(topo["plugin"], "files"); got != 1 {
		t.Fatalf("expected exactly one files plugin entry, got %d (%#v)", got, topo["plugin"])
	}

	groups := getMap(topo["groups"])
	all := getMap(groups["all"])
	if got := countStringInList(all["config"], "snmp_config"); got != 0 {
		t.Fatalf("expected groups.all.config snmp_config to be removed, got %d (%#v)", got, all["config"])
	}
	eos := getMap(groups["eos"])
	if got := countStringInList(eos["config"], "skyforge_eos_auth"); got != 1 {
		t.Fatalf("expected exactly one skyforge_eos_auth entry, got %d (%#v)", got, eos["config"])
	}

	nodes := getMap(topo["nodes"])
	r1 := getMap(nodes["r1"])
	h1 := getMap(nodes["h1"])
	if got := countStringInList(r1["config"], "snmp_config"); got != 1 {
		t.Fatalf("expected exactly one node snmp_config entry on r1, got %d (%#v)", got, r1["config"])
	}
	if got := countStringInList(h1["config"], "snmp_config"); got != 0 {
		t.Fatalf("expected linux node h1 snmp_config to be removed, got %d (%#v)", got, h1["config"])
	}

	configlets := getMap(topo["configlets"])
	snmpCfg := getMap(configlets["snmp_config"])
	if got := strings.TrimSpace(fmt.Sprintf("%v", snmpCfg["iol"])); got != "custom-iol-template" {
		t.Fatalf("expected existing iol template to be preserved, got %q", got)
	}
	if got := strings.TrimSpace(fmt.Sprintf("%v", snmpCfg["eos"])); got == "" {
		t.Fatalf("expected generated eos template to be present")
	}
	eosAuthCfg := getMap(configlets["skyforge_eos_auth"])
	if got := strings.TrimSpace(fmt.Sprintf("%v", eosAuthCfg["eos"])); got != "custom-eos-auth" {
		t.Fatalf("expected existing eos auth template to be preserved, got %q", got)
	}

	defaults := getMap(topo["defaults"])
	snmp := getMap(defaults["snmp"])
	if got := strings.TrimSpace(fmt.Sprintf("%v", snmp["trap_host"])); got != "" {
		t.Fatalf("expected empty defaults.snmp.trap_host, got %q", got)
	}
	if _, ok := snmp["trap_port"]; ok {
		t.Fatalf("expected defaults.snmp.trap_port to be omitted when trapPort=0")
	}
}

func TestPatchNetlabTopologyYAMLForSnmp_PreservesGroupAutoCreate(t *testing.T) {
	src := []byte(`
name: test
groups:
  _auto_create: true
  hosts:
    members: [h1]
    device: linux
  routers:
    members: [r1]
nodes:
  r1:
    device: nxos
`)
	out, err := patchNetlabTopologyYAMLForSnmp(src, "token-xyz", "", 0)
	if err != nil {
		t.Fatalf("patch failed: %v", err)
	}
	topo := parseYAMLMap(t, out)
	groups := getMap(topo["groups"])
	if v, ok := groups["_auto_create"].(bool); !ok || !v {
		t.Fatalf("expected groups._auto_create=true to be preserved, got %#v", groups["_auto_create"])
	}
}
