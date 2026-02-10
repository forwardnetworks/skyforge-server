package taskengine

import "strings"

// vrnetlabPinnedImages provides a last-resort rewrite map for vrnetlab images that
// are known to have multiple tags in circulation, where the unpinned/legacy tag is
// likely to break Skyforge connectivity checks (most commonly, SSH readiness).
//
// NOTE: This is intentionally small and only covers images we *must* pin for
// correctness. Netlab defaults remain the primary source of truth.
var vrnetlabPinnedImages = map[string]string{
	// Dell OS10 (FTOSv) is very large and can be present on nodes with an older cached digest.
	// Pin to the expected digest to ensure fresh pulls when the tag is updated.
	"ghcr.io/forwardnetworks/vrnetlab/vr-ftosv:10.6.1.0.24V": "ghcr.io/forwardnetworks/vrnetlab/vr-ftosv@sha256:1cde7dd305c5ebead38ecaba4d0ec694cb4ad4bb835dc8d11dcc46fee1279968",
	"vrnetlab/vr-ftosv:10.6.1.0.24V":                         "ghcr.io/forwardnetworks/vrnetlab/vr-ftosv@sha256:1cde7dd305c5ebead38ecaba4d0ec694cb4ad4bb835dc8d11dcc46fee1279968",
}

func rewritePinnedVrnetlabImage(image string) (string, bool) {
	image = strings.TrimSpace(image)
	if image == "" {
		return "", false
	}

	// IOSv/IOSvL2: pin to the Skyforge-tuned tags that preserve upstream behavior while
	// making SSH reachable reliably in Kubernetes (QEMU hostfwd bound to localhost + pod-IP proxy).
	//
	// This keeps templates using either upstream tags or older -skyforgeN tags working.
	if strings.Contains(image, "vrnetlab/cisco_vios:15.9.3") {
		// Pin to a digest so clusters with imagePullPolicy=IfNotPresent can't get stuck on an older
		// locally cached tag. This digest corresponds to :15.9.3-skyforge19 linux/amd64.
		return "ghcr.io/forwardnetworks/vrnetlab/cisco_vios@sha256:aa575d17f99775a71a6f076484c5998c2cf400c5524bd30d48dedbbf9e36f5c7", true
	}
	if strings.Contains(image, "vrnetlab/cisco_viosl2:15.2") {
		// Digest corresponds to :15.2-skyforge18 linux/amd64.
		return "ghcr.io/forwardnetworks/vrnetlab/cisco_viosl2@sha256:c8fccd0aef63187c371df881c094ab4ddca6d890c98f698365cafe0662a8442b", true
	}

	if pinned, ok := vrnetlabPinnedImages[image]; ok && strings.TrimSpace(pinned) != "" {
		return pinned, true
	}
	return image, false
}

// rewriteVrnetlabImageForCluster rewrites "vrnetlab/*" (dockerhub-style) images
// into our GHCR namespace so clabernetes can pull consistently.
//
// Netlab templates typically reference upstream tags like "vrnetlab/juniper_vmx:18.2R1.9".
// For Skyforge we mirror those images in GHCR as "ghcr.io/forwardnetworks/vrnetlab/<name>:<tag>".
//
// This function also applies the pinned image overrides (for known-problematic tags).
func rewriteVrnetlabImageForCluster(image string) (string, bool) {
	image = strings.TrimSpace(image)
	if image == "" {
		return "", false
	}

	// First apply deterministic pinning (may also change registry).
	if pinned, ok := rewritePinnedVrnetlabImage(image); ok {
		return pinned, true
	}

	// Normalize explicit docker.io registry references.
	if strings.HasPrefix(image, "docker.io/vrnetlab/") {
		return "ghcr.io/forwardnetworks/vrnetlab/" + strings.TrimPrefix(image, "docker.io/vrnetlab/"), true
	}

	// Normalize bare "vrnetlab/..." images.
	if strings.HasPrefix(image, "vrnetlab/") {
		return "ghcr.io/forwardnetworks/" + image, true
	}

	return image, false
}
