package taskengine

import "testing"

func TestValidateNoLegacyIOSVMTopology_RejectsLegacyKind(t *testing.T) {
	topology := []byte(`
name: test
topology:
  nodes:
    r1:
      kind: cisco_vios
      image: ghcr.io/forwardnetworks/vrnetlab/cisco_vios:15.9.3
`)
	err := validateNoLegacyIOSVMTopology(topology)
	if err == nil {
		t.Fatalf("expected legacy kind rejection")
	}
}

func TestValidateNoLegacyIOSVMTopology_RejectsLegacyImage(t *testing.T) {
	topology := []byte(`
name: test
topology:
  nodes:
    r1:
      kind: unknown-kind
      image: ghcr.io/forwardnetworks/vrnetlab/vr-csr:17.03.04
`)
	err := validateNoLegacyIOSVMTopology(topology)
	if err == nil {
		t.Fatalf("expected legacy image rejection")
	}
}

func TestValidateNoLegacyIOSVMTopology_AllowsIOL(t *testing.T) {
	topology := []byte(`
name: test
topology:
  nodes:
    r1:
      kind: cisco_iol
      image: ghcr.io/forwardnetworks/vrnetlab/cisco_iol:17.16.01a
    r2:
      kind: cisco_ioll2
      image: ghcr.io/forwardnetworks/vrnetlab/cisco_iol:L2-17.16.01a
`)
	err := validateNoLegacyIOSVMTopology(topology)
	if err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}
}
