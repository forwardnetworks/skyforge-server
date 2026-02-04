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
	//
	// Exception: IOL (IOU) does not expose a vrnetlab telnet console in the container,
	// so falling back to a shell is more useful than a broken telnet session.
	if strings.Contains(image, "cisco_iol") {
		return "sh"
	}
	return "telnet 127.0.0.1 5000"
}
