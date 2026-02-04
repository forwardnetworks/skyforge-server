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
//
func NormalizeCommand(command string) string {
	command = strings.TrimSpace(command)
	if command == "" {
		return "sh"
	}
	return command
}

func VrnetlabDefaultCommand(image string) string {
	image = strings.ToLower(strings.TrimSpace(image))
	// Most vrnetlab-backed nodes expose the NOS console over telnet on localhost:5000.
	return "telnet 127.0.0.1 5000"
}
