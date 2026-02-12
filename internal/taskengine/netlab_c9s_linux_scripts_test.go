package taskengine

import "testing"

func TestLinuxScriptModulesFromBinds(t *testing.T) {
	nodeCfg := map[string]any{
		"binds": []any{
			"node_files/H1/initial:/etc/config/01-initial.sh",
			"node_files/H1/routing:/etc/config/02-routing.sh",
			"/tmp/skyforge-c9s/topo/node_files/H1/snmp_config:/etc/config/03-snmp_config.sh",
			"node_files/-shared-hosts:/etc/hosts:ro",
			"node_files/H1/initial:/etc/config/01-initial.sh",
			"node_files/H1/startup.partial.config:/config/startup-config.cfg",
		},
	}

	got := linuxScriptModulesFromBinds(nodeCfg)
	want := []string{"initial", "routing", "snmp_config"}
	if len(got) != len(want) {
		t.Fatalf("unexpected module count got=%d want=%d (%#v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("unexpected module order at %d got=%q want=%q (%#v)", i, got[i], want[i], got)
		}
	}
}
