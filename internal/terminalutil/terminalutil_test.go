package terminalutil

import "testing"

func TestNormalizeCommand(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"", "sh"},
		{"   ", "sh"},
		{"sh", "sh"},
		{"cli", "cli"},
		{"CLI", "CLI"},
		{"  cli  ", "cli"},
		{"telnet 127.0.0.1 5000", "telnet 127.0.0.1 5000"},
	}

	for _, tt := range tests {
		if got := NormalizeCommand(tt.in); got != tt.want {
			t.Fatalf("NormalizeCommand(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestVrnetlabDefaultCommand(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"ghcr.io/forwardnetworks/vrnetlab/vr-vmx:18.2R1.9", "telnet 127.0.0.1 5000"},
		{"vrnetlab/juniper_vjunos-router:23.4R2-S2.1", "telnet 127.0.0.1 5000"},
		{"ghcr.io/forwardnetworks/vrnetlab/cisco_iol:17.16.01a", "telnet 127.0.0.1 5000"},
	}

	for _, tt := range tests {
		if got := VrnetlabDefaultCommand(tt.in); got != tt.want {
			t.Fatalf("VrnetlabDefaultCommand(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestIsCEOSImage(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"", false},
		{"ceos:4.32.0F", true},
		{"ghcr.io/forwardnetworks/ceos:4.31.1F", true},
		{"docker.io/arista/ceos:4.30.2F", true},
		{"ghcr.io/forwardnetworks/vrnetlab/vr-vmx:18.2R1.9", false},
	}

	for _, tt := range tests {
		if got := IsCEOSImage(tt.in); got != tt.want {
			t.Fatalf("IsCEOSImage(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestIsVrnetlabImage(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"", false},
		{"ghcr.io/forwardnetworks/vrnetlab/vr-vmx:18.2R1.9", true},
		{"vrnetlab/juniper_vjunos-router:23.4R2-S2.1", true},
		{"ghcr.io/someone/other:latest", false},
	}

	for _, tt := range tests {
		if got := IsVrnetlabImage(tt.in); got != tt.want {
			t.Fatalf("IsVrnetlabImage(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}
