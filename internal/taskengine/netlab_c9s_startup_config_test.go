package taskengine

import (
	"context"
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

func TestInjectNetlabC9sVrnetlabStartupConfig_IOSFamily_SkipsStartupConfigAndRewritesIOSvImages(t *testing.T) {
	// Covers the "IOS-family" fast path where we must:
	// - remove any generated "startup-config" references (we don't mount them)
	// - rewrite IOSv/IOSvL2 images to our tuned skyforge builds
	// - not attempt any Kubernetes ConfigMap injection (overrideData stays empty)
	in := []byte(`
topology:
  nodes:
    r1:
      kind: cisco_vios
      image: ghcr.io/forwardnetworks/vrnetlab/cisco_vios:15.9.3
      startup-config: /config/startup-config.cfg
    r2:
      kind: cisco_viosl2
      image: ghcr.io/forwardnetworks/vrnetlab/cisco_viosl2:15.2
      startup-config: /config/startup-config.cfg
    r3:
      kind: vr-csr
      image: ghcr.io/forwardnetworks/vrnetlab/vr-csr:17.03.04
      startup-config: /config/startup-config.cfg
`)

	outYAML, outMounts, err := injectNetlabC9sVrnetlabStartupConfig(
		context.Background(),
		"ws-test",
		"lab",
		in,
		map[string][]c9sFileFromConfigMap{"r1": {}, "r2": {}, "r3": {}},
		noopLogger{},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if outMounts == nil {
		t.Fatalf("expected mounts map")
	}
	if len(outMounts["r1"]) != 0 || len(outMounts["r2"]) != 0 || len(outMounts["r3"]) != 0 {
		t.Fatalf("expected no mount injections for ios-family fast path; got: %+v", outMounts)
	}

	var topo map[string]any
	if err := yaml.Unmarshal(outYAML, &topo); err != nil {
		t.Fatalf("failed to parse output yaml: %v", err)
	}
	topology, _ := topo["topology"].(map[string]any)
	nodes, _ := topology["nodes"].(map[string]any)
	if len(nodes) != 3 {
		t.Fatalf("expected 3 nodes, got %d", len(nodes))
	}

	r1, _ := nodes["r1"].(map[string]any)
	if got := r1["image"]; got != "ghcr.io/forwardnetworks/vrnetlab/cisco_vios:15.9.3-skyforge8" {
		t.Fatalf("r1 image mismatch: %v", got)
	}
	if _, ok := r1["startup-config"]; ok {
		t.Fatalf("r1 should not include startup-config")
	}

	r2, _ := nodes["r2"].(map[string]any)
	if got := r2["image"]; got != "ghcr.io/forwardnetworks/vrnetlab/cisco_viosl2:15.2-skyforge8" {
		t.Fatalf("r2 image mismatch: %v", got)
	}
	if _, ok := r2["startup-config"]; ok {
		t.Fatalf("r2 should not include startup-config")
	}

	r3, _ := nodes["r3"].(map[string]any)
	// We intentionally do not rewrite CSR image tags here, but we must still remove startup-config.
	if got := r3["image"]; got != "ghcr.io/forwardnetworks/vrnetlab/vr-csr:17.03.04" {
		t.Fatalf("r3 image mismatch: %v", got)
	}
	if _, ok := r3["startup-config"]; ok {
		t.Fatalf("r3 should not include startup-config")
	}
}

func TestInjectNetlabC9sVrnetlabStartupConfig_JunosFamily_SkipsStartupConfigInjection(t *testing.T) {
	in := []byte(`
topology:
  nodes:
    mx1:
      kind: vr-vmx
      image: ghcr.io/forwardnetworks/vrnetlab/vr-vmx:18.2R1.9
      startup-config: /config/startup-config.cfg
    r1:
      kind: juniper_vjunos-router
      image: ghcr.io/forwardnetworks/vrnetlab/juniper_vjunos-router:23.4R2-S2.1
      startup-config: /config/startup-config.cfg
    s1:
      kind: juniper_vjunos-switch
      image: ghcr.io/forwardnetworks/vrnetlab/juniper_vjunos-switch:23.4R2-S2.1
      startup-config: /config/startup-config.cfg
`)

	outYAML, outMounts, err := injectNetlabC9sVrnetlabStartupConfig(
		context.Background(),
		"ws-test",
		"lab",
		in,
		map[string][]c9sFileFromConfigMap{"mx1": {}, "r1": {}, "s1": {}},
		noopLogger{},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if outMounts == nil {
		t.Fatalf("expected mounts map")
	}
	if len(outMounts["mx1"]) != 0 || len(outMounts["r1"]) != 0 || len(outMounts["s1"]) != 0 {
		t.Fatalf("expected no mount injections for junos-family fast path; got: %+v", outMounts)
	}

	var topo map[string]any
	if err := yaml.Unmarshal(outYAML, &topo); err != nil {
		t.Fatalf("failed to parse output yaml: %v", err)
	}
	topology, _ := topo["topology"].(map[string]any)
	nodes, _ := topology["nodes"].(map[string]any)
	if len(nodes) != 3 {
		t.Fatalf("expected 3 nodes, got %d", len(nodes))
	}
	for _, n := range []string{"mx1", "r1", "s1"} {
		cfg, _ := nodes[n].(map[string]any)
		if _, ok := cfg["startup-config"]; ok {
			t.Fatalf("%s should not include startup-config", n)
		}
	}
}
