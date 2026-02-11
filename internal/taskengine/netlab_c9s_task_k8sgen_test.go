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
nodes:
  r1:
    device: iol
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
	if !listContainsString(all["config"], "snmp_config") {
		t.Fatalf("expected groups.all.config to include snmp_config, got %#v", all["config"])
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
}

func TestPatchNetlabTopologyYAMLForSnmp_NoDupesAndPreservesExistingTemplate(t *testing.T) {
	src := []byte(`
name: test
plugin: [files]
groups:
  all:
    config: [initial, snmp_config]
configlets:
  snmp_config:
    iol: "custom-iol-template"
nodes:
  r1:
    device: iol
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
	if got := countStringInList(all["config"], "snmp_config"); got != 1 {
		t.Fatalf("expected exactly one snmp_config entry, got %d (%#v)", got, all["config"])
	}

	configlets := getMap(topo["configlets"])
	snmpCfg := getMap(configlets["snmp_config"])
	if got := strings.TrimSpace(fmt.Sprintf("%v", snmpCfg["iol"])); got != "custom-iol-template" {
		t.Fatalf("expected existing iol template to be preserved, got %q", got)
	}
	if got := strings.TrimSpace(fmt.Sprintf("%v", snmpCfg["eos"])); got == "" {
		t.Fatalf("expected generated eos template to be present")
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
