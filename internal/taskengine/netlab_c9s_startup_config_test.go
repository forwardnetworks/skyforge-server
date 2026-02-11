package taskengine

import "testing"

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
		"devices.eos.clab.group_vars.netlab_config_mode=sh",
		"devices.ios.clab.group_vars.netlab_config_mode = startup",
		"devices.junos.clab.group_vars.netlab_config_mode=\"startup\"",
		"devices.nxos.group_vars.netlab_config_mode=startup", // wrong path
		"devices.eos.clab.group_vars.ansible_user=admin",     // wrong key
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
