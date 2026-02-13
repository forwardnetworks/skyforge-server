package taskengine

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func configHas(v any, target string) bool {
	switch vv := v.(type) {
	case string:
		return vv == target
	case []any:
		for _, item := range vv {
			if configHas(item, target) {
				return true
			}
		}
	case []string:
		for _, item := range vv {
			if item == target {
				return true
			}
		}
	}
	return false
}

func TestPatchNetlabTopologyYAMLForSnmp_ScopesByNodeDevice(t *testing.T) {
	input := []byte(`
groups:
  all:
    config: [initial, snmp_config]
defaults:
  device: eos
nodes:
  h1:
    device: linux
  r1:
    device: nxos
  r2: {}
`)

	out, err := patchNetlabTopologyYAMLForSnmp(input, "public", "10.0.0.10", 162)
	if err != nil {
		t.Fatalf("patch failed: %v", err)
	}

	var topo map[string]any
	if err := yaml.Unmarshal(out, &topo); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}

	groups, _ := topo["groups"].(map[string]any)
	all, _ := groups["all"].(map[string]any)
	if configHas(all["config"], "snmp_config") {
		t.Fatalf("groups.all.config should not include snmp_config")
	}

	nodes, _ := topo["nodes"].(map[string]any)
	h1, _ := nodes["h1"].(map[string]any)
	r1, _ := nodes["r1"].(map[string]any)
	r2, _ := nodes["r2"].(map[string]any)

	if configHas(h1["config"], "snmp_config") {
		t.Fatalf("linux node h1 should not include snmp_config")
	}
	if !configHas(r1["config"], "snmp_config") {
		t.Fatalf("non-linux node r1 should include snmp_config")
	}
	if !configHas(r2["config"], "snmp_config") {
		t.Fatalf("default-device node r2 should include snmp_config")
	}

	defaults, _ := topo["defaults"].(map[string]any)
	snmp, _ := defaults["snmp"].(map[string]any)
	if snmp["community"] != "public" {
		t.Fatalf("unexpected defaults.snmp.community: %#v", snmp["community"])
	}
	if snmp["trap_host"] != "10.0.0.10" {
		t.Fatalf("unexpected defaults.snmp.trap_host: %#v", snmp["trap_host"])
	}
}

func TestPatchNetlabTopologyYAMLForSnmp_ResolvesGroupDevices(t *testing.T) {
	input := []byte(`
groups:
  routers:
    device: iosv
    members: [r3]
  linuxhosts:
    device: linux
defaults:
  device: eos
nodes:
  r3: {}
  h2:
    group: linuxhosts
  h3:
    groups: [linuxhosts]
  h4: {}
`)

	out, err := patchNetlabTopologyYAMLForSnmp(input, "public", "", 162)
	if err != nil {
		t.Fatalf("patch failed: %v", err)
	}

	var topo map[string]any
	if err := yaml.Unmarshal(out, &topo); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	nodes, _ := topo["nodes"].(map[string]any)
	r3, _ := nodes["r3"].(map[string]any)
	h2, _ := nodes["h2"].(map[string]any)
	h3, _ := nodes["h3"].(map[string]any)
	h4, _ := nodes["h4"].(map[string]any)

	if !configHas(r3["config"], "snmp_config") {
		t.Fatalf("group-member router r3 should include snmp_config")
	}
	if configHas(h2["config"], "snmp_config") {
		t.Fatalf("group linux node h2 should not include snmp_config")
	}
	if configHas(h3["config"], "snmp_config") {
		t.Fatalf("groups-list linux node h3 should not include snmp_config")
	}
	if !configHas(h4["config"], "snmp_config") {
		t.Fatalf("default non-linux node h4 should include snmp_config")
	}
}
