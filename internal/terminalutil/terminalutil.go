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

// NormalizeCommand applies compatibility shims for in-browser terminals.
//
// The Skyforge UI historically used `cli` for Junos-like nodes, but most
// clabernetes/vrnetlab Junos images don't ship a `cli` binary in the container
// filesystem. They *do* expose the device console over telnet on localhost:5000
// (vrnetlab convention).
func NormalizeCommand(command string) string {
	command = strings.TrimSpace(command)
	if command == "" {
		return "sh"
	}
	if strings.EqualFold(command, "cli") {
		return "telnet 127.0.0.1 5000"
	}
	return command
}
