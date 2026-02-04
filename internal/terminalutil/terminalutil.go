package terminalutil

import "strings"

func IsVrnetlabImage(image string) bool {
	image = strings.ToLower(strings.TrimSpace(image))
	if image == "" {
		return false
	}
	// ghcr.io/forwardnetworks/vrnetlab/vr-vmx:18.2R1.9
	// vrnetlab/juniper_vjunos-router:23.4R2-S2.1
	return strings.Contains(image, "/vrnetlab/") || strings.HasPrefix(image, "vrnetlab/")
}

func IsCiscoIOLImage(image string) bool {
	image = strings.ToLower(strings.TrimSpace(image))
	return strings.Contains(image, "cisco_iol")
}

func IsCEOSImage(image string) bool {
	image = strings.ToLower(strings.TrimSpace(image))
	if image == "" {
		return false
	}
	// Common cEOS images:
	// - ceos:4.32.0F
	// - ghcr.io/<org>/ceos:...
	// - docker.io/arista/ceos:...
	if strings.Contains(image, "ceos") {
		return true
	}
	return false
}

// NormalizeCommand applies compatibility shims for in-browser terminals.
func NormalizeCommand(command string) string {
	command = strings.TrimSpace(command)
	if command == "" {
		return "sh"
	}
	return command
}

// VrnetlabConsoleCommand is a stable identifier used for session takeover in the terminal UX.
const VrnetlabConsoleCommand = "vrnetlab-console"

func VrnetlabConsoleExec(image string) []string {
	// Most vrnetlab-backed nodes expose the NOS console over TCP on localhost:5000.
	//
	// We intentionally avoid relying on `telnet` being installed in the NOS container.
	// Instead we use bash's /dev/tcp to create a bidirectional stream.
	//
	// NOTE: This does not implement telnet option negotiation; in practice vrnetlab
	// console endpoints are simple enough for this to work well across our images.
	_ = image // reserved for future per-image quirks
	script := `set -euo pipefail
exec 3<>/dev/tcp/127.0.0.1/5000
trap 'kill 0' EXIT
cat <&3 &
cat >&3`
	return []string{"bash", "-lc", script}
}
