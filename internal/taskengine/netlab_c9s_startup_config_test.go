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
