package taskengine

import "testing"

func TestPickNetlabC9sEOSConfigSnippet_PrefersConfig(t *testing.T) {
	topology := "t1"
	node := "L1"
	mountRoot := "/tmp/skyforge-c9s/" + topology + "/node_files/" + node + "/"
	got := pickNetlabC9sEOSConfigSnippet(topology, node, []c9sFileFromConfigMap{
		{FilePath: mountRoot + "L1.cfg", ConfigMapName: "cm", ConfigMapPath: "L1.cfg"},
		{FilePath: mountRoot + "config", ConfigMapName: "cm", ConfigMapPath: "config"},
	})
	if got != mountRoot+"config" {
		t.Fatalf("unexpected: %q", got)
	}
}

func TestPickNetlabC9sEOSConfigSnippet_SkipsNonCfgFiles(t *testing.T) {
	topology := "t1"
	node := "L1"
	mountRoot := "/tmp/skyforge-c9s/" + topology + "/node_files/" + node + "/"
	got := pickNetlabC9sEOSConfigSnippet(topology, node, []c9sFileFromConfigMap{
		{FilePath: mountRoot + "hosts.yml", ConfigMapName: "cm", ConfigMapPath: "hosts.yml"},
		{FilePath: mountRoot + "README.md", ConfigMapName: "cm", ConfigMapPath: "README.md"},
	})
	if got != "" {
		t.Fatalf("expected empty, got %q", got)
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
