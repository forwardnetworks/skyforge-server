package taskengine

import "testing"

func TestContainerlabNodeSpecs(t *testing.T) {
	topology := `
topology:
  nodes:
    r1:
      kind: nxos
      image: ghcr.io/forwardnetworks/vrnetlab/vr-n9kv:9.3.8
    r2:
      kind: iosv
      image: ghcr.io/forwardnetworks/vrnetlab/cisco_vios:15.9.3
`

	specs, err := containerlabNodeSpecs(topology)
	if err != nil {
		t.Fatalf("containerlabNodeSpecs error: %v", err)
	}
	if len(specs) != 2 {
		t.Fatalf("node count: got=%d want=2", len(specs))
	}

	if got := specs["r1"].Kind; got != "nxos" {
		t.Fatalf("r1 kind: got=%q want=%q", got, "nxos")
	}
	if got := specs["r1"].Image; got != "ghcr.io/forwardnetworks/vrnetlab/vr-n9kv:9.3.8" {
		t.Fatalf("r1 image: got=%q", got)
	}

	kinds, err := containerlabNodeKinds(topology)
	if err != nil {
		t.Fatalf("containerlabNodeKinds error: %v", err)
	}
	if got := kinds["r2"]; got != "iosv" {
		t.Fatalf("r2 kind: got=%q want=%q", got, "iosv")
	}
}
