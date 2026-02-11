package taskengine

import "testing"

func TestNOSResourceProfileForNode(t *testing.T) {
	p, matchedBy, ok := nosResourceProfileForNode("nxos", "ghcr.io/forwardnetworks/vrnetlab/vr-n9kv:9.3.8")
	if !ok {
		t.Fatalf("expected nxos profile match")
	}
	if p.CPURequest != "4000m" || p.MemoryRequest != "12Gi" {
		t.Fatalf("unexpected nxos profile: %+v", p)
	}
	if matchedBy == "" {
		t.Fatalf("expected non-empty matchedBy")
	}
}

func TestNOSResourceProfileNormalization(t *testing.T) {
	p, ok := nosResourceProfileForKind("juniper_vjunos-router")
	if !ok {
		t.Fatalf("expected normalized match for juniper_vjunos-router")
	}
	if p.CPURequest != "4000m" || p.MemoryRequest != "6Gi" {
		t.Fatalf("unexpected vjunos-router profile: %+v", p)
	}
}

func TestContainerImageBaseName(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{in: "ghcr.io/forwardnetworks/vrnetlab/vr-n9kv:9.3.8", want: "vr-n9kv"},
		{in: "ghcr.io/forwardnetworks/vrnetlab/cisco_vios@sha256:deadbeef", want: "cisco_vios"},
		{in: "vrnetlab/cisco_asav:9-16-4-57", want: "cisco_asav"},
	}
	for _, tc := range cases {
		if got := containerImageBaseName(tc.in); got != tc.want {
			t.Fatalf("containerImageBaseName(%q): got=%q want=%q", tc.in, got, tc.want)
		}
	}
}
