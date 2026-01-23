package taskengine

import (
	"encoding/json"
	"net"
	"strings"
)

// cniNetworkStatus is the schema used in the Multus network-status annotation:
// https://github.com/k8snetworkplumbingwg/multus-cni/blob/master/docs/how-to-use.md
type cniNetworkStatusEntry struct {
	Name      string   `json:"name"`
	Interface string   `json:"interface"`
	IPs       []string `json:"ips"`
	Mac       string   `json:"mac"`
	Gateway   []string `json:"gateway"`
	Default   bool     `json:"default"`
}

func parseCNIStatusIPForNetwork(raw, want string) (string, bool) {
	raw = strings.TrimSpace(raw)
	want = strings.TrimSpace(want)
	if raw == "" || want == "" {
		return "", false
	}

	var entries []cniNetworkStatusEntry
	if err := json.Unmarshal([]byte(raw), &entries); err != nil {
		return "", false
	}

	for _, e := range entries {
		name := strings.TrimSpace(e.Name)
		if name == "" {
			continue
		}
		if !cniNetNameMatches(name, want) {
			continue
		}
		for _, ip := range e.IPs {
			ip = strings.TrimSpace(ip)
			if ip == "" {
				continue
			}
			if strings.Contains(ip, "/") {
				host, _, err := net.ParseCIDR(ip)
				if err == nil && host != nil {
					return host.String(), true
				}
				ip = strings.SplitN(ip, "/", 2)[0]
			}
			if net.ParseIP(ip) != nil {
				return ip, true
			}
		}
	}
	return "", false
}

func cniNetNameMatches(got, want string) bool {
	got = strings.TrimSpace(got)
	want = strings.TrimSpace(want)
	if got == "" || want == "" {
		return false
	}
	if got == want {
		return true
	}
	// Allow matching "vrnetlab-mgmt" against "kube-system/vrnetlab-mgmt".
	if !strings.Contains(want, "/") {
		if idx := strings.LastIndex(got, "/"); idx >= 0 {
			got = got[idx+1:]
		}
		return got == want
	}
	// Allow matching "kube-system/vrnetlab-mgmt" against "vrnetlab-mgmt" (unlikely but harmless).
	if idx := strings.LastIndex(want, "/"); idx >= 0 {
		return strings.TrimSpace(want[idx+1:]) == got
	}
	return false
}
