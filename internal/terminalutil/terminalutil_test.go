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
		{"ghcr.io/forwardnetworks/vrnetlab/cisco_iol:17.16.01a", "sh"},
	}

	for _, tt := range tests {
		if got := VrnetlabDefaultCommand(tt.in); got != tt.want {
			t.Fatalf("VrnetlabDefaultCommand(%q) = %q, want %q", tt.in, got, tt.want)
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
