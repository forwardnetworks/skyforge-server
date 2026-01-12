package skyforge

import (
	"strings"
)

func netlabDisabledToolsFromEnv(env map[string]string) map[string]bool {
	disabled := map[string]bool{}
	if len(env) == 0 {
		return disabled
	}
	if envTruthy(env["SKYFORGE_NETLAB_DISABLE_GRAPHITE"]) {
		disabled["graphite"] = true
	}
	if raw := strings.TrimSpace(env["SKYFORGE_NETLAB_DISABLE_TOOLS"]); raw != "" {
		for _, part := range strings.Split(raw, ",") {
			name := strings.ToLower(strings.TrimSpace(part))
			if name == "" {
				continue
			}
			disabled[name] = true
		}
	}
	return disabled
}

