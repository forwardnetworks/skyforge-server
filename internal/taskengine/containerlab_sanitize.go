package taskengine

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

var (
	dns1035Re   = regexp.MustCompile(`[^a-z0-9-]+`)
	dns1035Trim = regexp.MustCompile(`^-+|-+$`)
)

func sanitizeDNS1035Label(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = dns1035Re.ReplaceAllString(value, "-")
	value = dns1035Trim.ReplaceAllString(value, "")

	if value == "" {
		return "n"
	}

	// Must start with a letter.
	if value[0] < 'a' || value[0] > 'z' {
		value = "n-" + value
	}

	// Must end with alphanumeric.
	for len(value) > 0 {
		last := value[len(value)-1]
		if (last >= 'a' && last <= 'z') || (last >= '0' && last <= '9') {
			break
		}
		value = strings.TrimRight(value, "-")
	}

	if value == "" {
		return "n"
	}

	if len(value) > 63 {
		value = value[:63]
		for len(value) > 0 {
			last := value[len(value)-1]
			if (last >= 'a' && last <= 'z') || (last >= '0' && last <= '9') {
				break
			}
			value = strings.TrimRight(value, "-")
		}
	}

	if value == "" {
		return "n"
	}

	return value
}

// sanitizeContainerlabYAMLForClabernetes ensures that node names are valid Kubernetes DNS-1035 labels
// so that clabernetes can safely derive Service/Deployment names from them.
//
// It returns the rewritten containerlab YAML and an old->new node name mapping.
func sanitizeContainerlabYAMLForClabernetes(containerlabYAML string) (string, map[string]string, error) {
	containerlabYAML = strings.TrimSpace(containerlabYAML)
	if containerlabYAML == "" {
		return "", nil, nil
	}

	var doc map[string]any
	if err := yaml.Unmarshal([]byte(containerlabYAML), &doc); err != nil {
		return "", nil, fmt.Errorf("failed to parse containerlab yaml: %w", err)
	}
	if doc == nil {
		return containerlabYAML, nil, nil
	}

	topology, ok := doc["topology"].(map[string]any)
	if !ok || topology == nil {
		return containerlabYAML, nil, nil
	}
	nodes, ok := topology["nodes"].(map[string]any)
	if !ok || nodes == nil || len(nodes) == 0 {
		return containerlabYAML, nil, nil
	}

	// Create deterministic mapping and avoid collisions.
	oldNames := make([]string, 0, len(nodes))
	for name := range nodes {
		oldNames = append(oldNames, name)
	}
	sort.Strings(oldNames)

	mapping := map[string]string{}
	used := map[string]bool{}
	for _, old := range oldNames {
		newName := sanitizeDNS1035Label(old)
		base := newName
		for i := 2; used[newName]; i++ {
			suffix := fmt.Sprintf("-%d", i)
			max := 63 - len(suffix)
			if max < 1 {
				newName = "n" + suffix
			} else if len(base) > max {
				newName = base[:max] + suffix
			} else {
				newName = base + suffix
			}
		}
		used[newName] = true
		if newName != old {
			mapping[old] = newName
		}
	}
	if len(mapping) == 0 {
		return containerlabYAML, nil, nil
	}

	newNodes := map[string]any{}
	for old, cfg := range nodes {
		newName := old
		if v, ok := mapping[old]; ok {
			newName = v
		}
		// Also rewrite any node_files binds that include the original node directory name.
		if cfgMap, ok := cfg.(map[string]any); ok {
			if bindsAny, ok := cfgMap["binds"]; ok {
				if bindsList, ok := bindsAny.([]any); ok && len(bindsList) > 0 {
					out := make([]any, 0, len(bindsList))
					for _, bAny := range bindsList {
						bind := strings.TrimSpace(fmt.Sprintf("%v", bAny))
						if bind == "" {
							continue
						}
						parts := strings.SplitN(bind, ":", 2)
						if len(parts) != 2 {
							out = append(out, bind)
							continue
						}
						hostPath := strings.TrimPrefix(strings.TrimSpace(parts[0]), "./")
						if strings.HasPrefix(hostPath, "node_files/") {
							rest := strings.TrimPrefix(hostPath, "node_files/")
							seg := strings.SplitN(rest, "/", 2)
							if len(seg) >= 1 {
								if mapped, ok := mapping[seg[0]]; ok {
									seg[0] = mapped
									rest = strings.Join(seg, "/")
									hostPath = "node_files/" + rest
								}
							}
						}
						out = append(out, hostPath+":"+parts[1])
					}
					cfgMap["binds"] = out
					cfg = cfgMap
				}
			}
		}
		newNodes[newName] = cfg
	}
	topology["nodes"] = newNodes

	// Rewrite link endpoints (e.g. "L1:eth1") to the sanitized node names.
	if linksAny, ok := topology["links"]; ok {
		if links, ok := linksAny.([]any); ok {
			for i, linkAny := range links {
				link, ok := linkAny.(map[string]any)
				if !ok || link == nil {
					continue
				}
				endpointsAny, ok := link["endpoints"]
				if !ok {
					continue
				}
				eps, ok := endpointsAny.([]any)
				if !ok || len(eps) == 0 {
					continue
				}
				out := make([]any, 0, len(eps))
				for _, epAny := range eps {
					ep := strings.TrimSpace(fmt.Sprintf("%v", epAny))
					if ep == "" || strings.HasPrefix(ep, "host:") {
						out = append(out, epAny)
						continue
					}
					parts := strings.SplitN(ep, ":", 2)
					if len(parts) != 2 {
						out = append(out, epAny)
						continue
					}
					if mapped, ok := mapping[parts[0]]; ok {
						ep = mapped + ":" + parts[1]
					}
					out = append(out, ep)
				}
				link["endpoints"] = out
				links[i] = link
			}
			topology["links"] = links
		}
	}

	doc["topology"] = topology

	out, err := yaml.Marshal(doc)
	if err != nil {
		return "", nil, fmt.Errorf("failed to encode containerlab yaml: %w", err)
	}
	return string(out), mapping, nil
}
