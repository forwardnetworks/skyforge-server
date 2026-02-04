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
		{"cli", "telnet 127.0.0.1 5000"},
		{"CLI", "telnet 127.0.0.1 5000"},
		{"  cli  ", "telnet 127.0.0.1 5000"},
		{"telnet 127.0.0.1 5000", "telnet 127.0.0.1 5000"},
	}

	for _, tt := range tests {
		if got := NormalizeCommand(tt.in); got != tt.want {
			t.Fatalf("NormalizeCommand(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

