package taskengine

import (
	"strings"
	"testing"
)

func TestPickNetlabC9sEOSConfigSnippets_OrdersKnownModules(t *testing.T) {
	topology := "t1"
	node := "L1"
	mountRoot := "/tmp/skyforge-c9s/" + topology + "/node_files/" + node + "/"
	got := pickNetlabC9sEOSConfigSnippets(topology, node, []c9sFileFromConfigMap{
		{FilePath: mountRoot + "bgp", ConfigMapName: "cm", ConfigMapPath: "bgp"},
		{FilePath: mountRoot + "initial", ConfigMapName: "cm", ConfigMapPath: "initial"},
		{FilePath: mountRoot + "normalize", ConfigMapName: "cm", ConfigMapPath: "normalize"},
	})
	if len(got) != 3 {
		t.Fatalf("expected 3 snippets, got %d", len(got))
	}
	if got[0] != mountRoot+"normalize" || got[1] != mountRoot+"initial" || got[2] != mountRoot+"bgp" {
		t.Fatalf("unexpected order: %#v", got)
	}
}

func TestPickNetlabC9sEOSConfigSnippets_SkipsNonSnippetFiles(t *testing.T) {
	topology := "t1"
	node := "L1"
	mountRoot := "/tmp/skyforge-c9s/" + topology + "/node_files/" + node + "/"
	got := pickNetlabC9sEOSConfigSnippets(topology, node, []c9sFileFromConfigMap{
		{FilePath: mountRoot + "hosts.yml", ConfigMapName: "cm", ConfigMapPath: "hosts.yml"},
		{FilePath: mountRoot + "template.j2", ConfigMapName: "cm", ConfigMapPath: "template.j2"},
		{FilePath: mountRoot + "config.yaml", ConfigMapName: "cm", ConfigMapPath: "config.yaml"},
	})
	if len(got) != 0 {
		t.Fatalf("expected empty, got %#v", got)
	}
}

func TestInjectEOSManagementSSH_AlreadyPresent(t *testing.T) {
	in := "hostname L1\nmanagement ssh\nend\n"
	out, changed := injectEOSManagementSSH(in)
	if changed {
		t.Fatalf("expected unchanged")
	}
	if out != in {
		t.Fatalf("expected output to equal input")
	}
}

func TestInjectEOSManagementSSH_InsertsBeforeEnd(t *testing.T) {
	in := "hostname L1\n!\nend\n"
	out, changed := injectEOSManagementSSH(in)
	if !changed {
		t.Fatalf("expected changed")
	}
	want := "hostname L1\n!\nmanagement ssh\nend\n"
	if out != want {
		t.Fatalf("unexpected output:\n%s", out)
	}
}

func TestInjectEOSManagementSSH_AppendsWhenNoEnd(t *testing.T) {
	in := "hostname L1\n!\n"
	out, changed := injectEOSManagementSSH(in)
	if !changed {
		t.Fatalf("expected changed")
	}
	want := "hostname L1\n!\nmanagement ssh\n"
	if out != want {
		t.Fatalf("unexpected output:\n%s", out)
	}
}

func TestInjectEOSManagementSSH_NormalizesCRLF(t *testing.T) {
	in := "hostname L1\r\nend\r\n"
	out, changed := injectEOSManagementSSH(in)
	if !changed {
		t.Fatalf("expected changed")
	}
	want := "hostname L1\nmanagement ssh\nend\n"
	if out != want {
		t.Fatalf("unexpected output:\n%q", out)
	}
}

func TestInjectEOSDefaultSSHUser_InsertsMissingAuthLinesEvenWithUser(t *testing.T) {
	in := "username bob privilege 15 secret bob\nend\n"
	out, changed := injectEOSDefaultSSHUser(in)
	if !changed {
		t.Fatalf("expected changed")
	}
	want := "username bob privilege 15 secret bob\nenable secret admin\naaa authentication login default local\naaa authorization exec default local\nend\n"
	if out != want {
		t.Fatalf("unexpected output:\n%s", out)
	}
}

func TestInjectEOSDefaultSSHUser_InsertsBeforeEnd(t *testing.T) {
	in := "hostname L1\n!\nend\n"
	out, changed := injectEOSDefaultSSHUser(in)
	if !changed {
		t.Fatalf("expected changed")
	}
	want := "hostname L1\n!\nusername admin privilege 15 secret admin\nenable secret admin\naaa authentication login default local\naaa authorization exec default local\nend\n"
	if out != want {
		t.Fatalf("unexpected output:\n%s", out)
	}
}

func TestInjectEOSDefaultSSHUser_AppendsWhenNoEnd(t *testing.T) {
	in := "hostname L1\n!\n"
	out, changed := injectEOSDefaultSSHUser(in)
	if !changed {
		t.Fatalf("expected changed")
	}
	want := "hostname L1\n!\nusername admin privilege 15 secret admin\nenable secret admin\naaa authentication login default local\naaa authorization exec default local\n"
	if out != want {
		t.Fatalf("unexpected output:\n%s", out)
	}
}

func TestShouldSkipNetlabInitialForTopology_NXOSAlwaysRequiresInitial(t *testing.T) {
	topology := []byte(`
topology:
  nodes:
    s1:
      kind: nxos
      image: ghcr.io/forwardnetworks/vrnetlab/vr-n9kv:9.3.14
      startup-config: /config/startup-config.cfg
    h1:
      kind: linux
      image: ghcr.io/srl-labs/network-multitool:latest
`)
	modeByDevice := map[string]string{
		"nxos":  "startup",
		"linux": "sh",
	}
	if shouldSkipNetlabInitialForTopology(topology, modeByDevice) {
		t.Fatalf("expected netlab initial to remain enabled when topology includes nxos")
	}
}

func TestShouldSkipNetlabInitialForTopology_NXOSWithoutStartupConfigRequiresInitial(t *testing.T) {
	topology := []byte(`
topology:
  nodes:
    s1:
      kind: nxos
      image: ghcr.io/forwardnetworks/vrnetlab/vr-n9kv:9.3.14
`)
	modeByDevice := map[string]string{
		"nxos": "startup",
	}
	if shouldSkipNetlabInitialForTopology(topology, modeByDevice) {
		t.Fatalf("expected netlab initial to remain enabled when nxos startup-config is missing")
	}
}

func TestValidateAndLogNetlabConfigModesForTopology_RejectsUnsupportedPair(t *testing.T) {
	topology := []byte(`
topology:
  nodes:
    s1:
      kind: nxos
      image: ghcr.io/forwardnetworks/vrnetlab/vr-n9kv:9.3.14
`)
	defaults := map[string]string{
		"nxos": "startup",
	}
	overrides := map[string]string{}
	effective := map[string]string{
		"nxos": "startup",
	}
	err := validateAndLogNetlabConfigModesForTopology(topology, defaults, overrides, effective, noopLogger{})
	if err == nil {
		t.Fatalf("expected unsupported nxos startup mode to fail validation")
	}
	if !strings.Contains(err.Error(), "does not support") {
		t.Fatalf("unexpected error: %v", err)
	}
}
