package taskengine

import "strings"

// vrnetlabPinnedImages provides a last-resort rewrite map for vrnetlab images that
// are known to have multiple tags in circulation, where the unpinned/legacy tag is
// likely to break Skyforge connectivity checks (most commonly, SSH readiness).
//
// NOTE: This is intentionally small and only covers images we *must* pin for
// correctness. Netlab defaults remain the primary source of truth.
var vrnetlabPinnedImages = map[string]string{
	// IOSv/IOSvL2 require deterministic SSH reachability in our vrnetlab launcher.
	"ghcr.io/forwardnetworks/vrnetlab/cisco_vios:15.9.3":   "ghcr.io/forwardnetworks/vrnetlab/cisco_vios:15.9.3-20260201-ssh3",
	"ghcr.io/forwardnetworks/vrnetlab/cisco_viosl2:15.2":   "ghcr.io/forwardnetworks/vrnetlab/cisco_viosl2:15.2-20260201-ssh3",
	"vrnetlab/cisco_vios:15.9.3":                           "ghcr.io/forwardnetworks/vrnetlab/cisco_vios:15.9.3-20260201-ssh3",
	"vrnetlab/cisco_viosl2:15.2":                           "ghcr.io/forwardnetworks/vrnetlab/cisco_viosl2:15.2-20260201-ssh3",
}

func rewritePinnedVrnetlabImage(image string) (string, bool) {
	image = strings.TrimSpace(image)
	if image == "" {
		return "", false
	}
	if pinned, ok := vrnetlabPinnedImages[image]; ok && strings.TrimSpace(pinned) != "" {
		return pinned, true
	}
	return image, false
}
