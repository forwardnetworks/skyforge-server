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

// CiscoIOLConsoleCommand is a stable identifier used for session takeover for Cisco IOL nodes.
const CiscoIOLConsoleCommand = "iol-console"

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

func CiscoIOLConsoleExec() []string {
	// Cisco IOL nodes typically expose an SSH server on localhost:22 in the launcher
	// network namespace, but do not expose a stable vrnetlab console port on :5000.
	//
	// We want the browser terminal to land directly in IOS without prompting for a
	// password. Use SSH_ASKPASS to provide the default credentials non-interactively.
	//
	// Notes:
	// - This runs in the launcher container (which has bash/ssh/setsid).
	// - We intentionally keep the credentials as the containerlab/netlab defaults.
	// - The session remains interactive after auth; the askpass is only used for login.
	script := `set -euo pipefail
export SKYFORGE_SSH_USERNAME="${SKYFORGE_SSH_USERNAME:-admin}"
export SKYFORGE_SSH_PASSWORD="${SKYFORGE_SSH_PASSWORD:-admin}"

askpass="$(mktemp)"
cat >"${askpass}" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "${SKYFORGE_SSH_PASSWORD:-}"
EOF
chmod +x "${askpass}"
export SSH_ASKPASS="${askpass}"
export SSH_ASKPASS_REQUIRE=force
export DISPLAY=1

exec setsid -w ssh \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  -o PreferredAuthentications=password \
  -o PubkeyAuthentication=no \
  "${SKYFORGE_SSH_USERNAME}@127.0.0.1"`

	return []string{"bash", "-lc", script}
}
