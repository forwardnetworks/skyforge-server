package skyforge

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"encore.dev/beta/errs"
)

type TopologyIntentDefaults struct {
	Device      string `json:"device,omitempty"`
	ImagePolicy string `json:"imagePolicy,omitempty"`
}

type TopologyIntentProtocols struct {
	BGP   bool `json:"bgp,omitempty"`
	OSPF  bool `json:"ospf,omitempty"`
	ISIS  bool `json:"isis,omitempty"`
	EVPN  bool `json:"evpn,omitempty"`
	VXLAN bool `json:"vxlan,omitempty"`
}

type TopologyIntentConstraints struct {
	RuntimeTargets []string `json:"runtimeTargets,omitempty"`
}

type TopologyIntentNode struct {
	ID    string  `json:"id"`
	Label string  `json:"label"`
	Role  string  `json:"role"`
	Kind  string  `json:"kind,omitempty"`
	Image string  `json:"image,omitempty"`
	X     float64 `json:"x"`
	Y     float64 `json:"y"`
}

type TopologyIntentLink struct {
	ID string `json:"id"`
	A  string `json:"a"`
	B  string `json:"b"`
}

type TopologyIntentSpec struct {
	Name        string                    `json:"name"`
	Defaults    TopologyIntentDefaults    `json:"defaults"`
	Protocols   TopologyIntentProtocols   `json:"protocols,omitempty"`
	Constraints TopologyIntentConstraints `json:"constraints,omitempty"`
	Nodes       []TopologyIntentNode      `json:"nodes"`
	Links       []TopologyIntentLink      `json:"links"`
	Assumptions []string                  `json:"assumptions,omitempty"`
	Warnings    []string                  `json:"warnings,omitempty"`
}

type UserAIGenerateTopologySpecRequest struct {
	Prompt string `json:"prompt"`
	Hints  struct {
		PreferredDevice string `json:"preferredDevice,omitempty"`
		TargetSize      string `json:"targetSize,omitempty"`
		IncludeHosts    *bool  `json:"includeHosts,omitempty"`
	} `json:"hints,omitempty"`
}

type UserAIGenerateTopologySpecResponse struct {
	Spec             TopologyIntentSpec `json:"spec"`
	NetlabYAML       string             `json:"netlabYaml"`
	ContainerlabYAML string             `json:"containerlabYaml"`
	GeneratedAt      string             `json:"generatedAt"`
}

var (
	reSpines       = regexp.MustCompile(`\b(\d+)\s*spines?\b`)
	reLeaves       = regexp.MustCompile(`\b(\d+)\s*leaves?\b`)
	reHostsPerLeaf = regexp.MustCompile(`\b(\d+)\s*hosts?\s*/\s*leaf\b`)
	reHosts        = regexp.MustCompile(`\b(\d+)\s*hosts?\b`)
)

func parseCount(re *regexp.Regexp, input string) int {
	m := re.FindStringSubmatch(input)
	if len(m) != 2 {
		return 0
	}
	n, err := strconv.Atoi(strings.TrimSpace(m[1]))
	if err != nil || n < 0 {
		return 0
	}
	return n
}

func detectNetlabDevice(prompt, preferred string) string {
	s := strings.ToLower(strings.TrimSpace(preferred))
	if s == "" {
		s = strings.ToLower(prompt)
	}
	switch {
	case strings.Contains(s, "iol"):
		return "iol"
	case strings.Contains(s, "nxos"), strings.Contains(s, "nx-os"), strings.Contains(s, "n9k"), strings.Contains(s, "n9kv"):
		return "nxos"
	case strings.Contains(s, "vmx"):
		return "vmx"
	case strings.Contains(s, "vsrx"), strings.Contains(s, "srx"):
		return "vsrx"
	case strings.Contains(s, "ftos"), strings.Contains(s, "os10"), strings.Contains(s, "dellos10"):
		return "dellos10"
	default:
		return "eos"
	}
}

func containerlabKindAndImage(device string) (string, string) {
	switch strings.ToLower(strings.TrimSpace(device)) {
	case "iol":
		return "cisco_iol", "ghcr.io/forwardnetworks/vrnetlab/cisco_iol:latest"
	case "nxos":
		return "vr-n9kv", "ghcr.io/forwardnetworks/vrnetlab/vr-n9kv:latest"
	case "vmx":
		return "vr-vmx", "ghcr.io/forwardnetworks/vrnetlab/vr-vmx:latest"
	case "vsrx":
		return "vr-vsrx", "ghcr.io/forwardnetworks/vrnetlab/vr-vsrx:latest"
	case "dellos10":
		return "vr-ftosv", "ghcr.io/forwardnetworks/vrnetlab/vr-ftosv:latest"
	default:
		return "ceos", "ghcr.io/srl-labs/ceos:latest"
	}
}

func detectProtocols(prompt string) TopologyIntentProtocols {
	p := strings.ToLower(prompt)
	return TopologyIntentProtocols{
		BGP:   strings.Contains(p, "bgp"),
		OSPF:  strings.Contains(p, "ospf"),
		ISIS:  strings.Contains(p, "isis"),
		EVPN:  strings.Contains(p, "evpn"),
		VXLAN: strings.Contains(p, "vxlan"),
	}
}

func buildSpecFromPrompt(req *UserAIGenerateTopologySpecRequest) TopologyIntentSpec {
	prompt := strings.TrimSpace(req.Prompt)
	lower := strings.ToLower(prompt)
	device := detectNetlabDevice(prompt, req.Hints.PreferredDevice)
	switchKind, switchImage := containerlabKindAndImage(device)
	spec := TopologyIntentSpec{
		Name: sanitizeDeploymentName(prompt, "ai-lab"),
		Defaults: TopologyIntentDefaults{
			Device:      device,
			ImagePolicy: "catalog-only",
		},
		Protocols: detectProtocols(prompt),
		Constraints: TopologyIntentConstraints{
			RuntimeTargets: []string{"netlab", "containerlab"},
		},
		Nodes:       []TopologyIntentNode{},
		Links:       []TopologyIntentLink{},
		Assumptions: []string{},
		Warnings:    []string{},
	}

	isClos := strings.Contains(lower, "clos") || (strings.Contains(lower, "leaf") && strings.Contains(lower, "spine"))
	if isClos {
		spines := parseCount(reSpines, lower)
		if spines == 0 {
			spines = 2
			spec.Assumptions = append(spec.Assumptions, "Defaulted spine count to 2")
		}
		leaves := parseCount(reLeaves, lower)
		if leaves == 0 {
			leaves = 2
			spec.Assumptions = append(spec.Assumptions, "Defaulted leaf count to 2")
		}
		hostsPerLeaf := parseCount(reHostsPerLeaf, lower)
		if hostsPerLeaf == 0 {
			if parseCount(reHosts, lower) > 0 {
				hostsPerLeaf = 1
			}
		}
		if req.Hints.IncludeHosts != nil && !*req.Hints.IncludeHosts {
			hostsPerLeaf = 0
		}

		x0 := 120.0
		dx := 260.0
		ySpine := 120.0
		yLeaf := 320.0
		yHost := 520.0

		spineIDs := make([]string, 0, spines)
		leafIDs := make([]string, 0, leaves)
		for i := 1; i <= spines; i++ {
			id := fmt.Sprintf("s%d", i)
			spineIDs = append(spineIDs, id)
			spec.Nodes = append(spec.Nodes, TopologyIntentNode{
				ID: id, Label: id, Role: "switch", Kind: switchKind, Image: switchImage,
				X: x0 + float64(i-1)*dx, Y: ySpine,
			})
		}
		for i := 1; i <= leaves; i++ {
			id := fmt.Sprintf("l%d", i)
			leafIDs = append(leafIDs, id)
			spec.Nodes = append(spec.Nodes, TopologyIntentNode{
				ID: id, Label: id, Role: "switch", Kind: switchKind, Image: switchImage,
				X: x0 + float64(i-1)*dx, Y: yLeaf,
			})
		}

		linkID := 1
		for _, l := range leafIDs {
			for _, s := range spineIDs {
				spec.Links = append(spec.Links, TopologyIntentLink{
					ID: fmt.Sprintf("e%d", linkID),
					A:  l,
					B:  s,
				})
				linkID++
			}
		}

		hostCounter := 1
		for li, l := range leafIDs {
			for hi := 0; hi < hostsPerLeaf; hi++ {
				hid := fmt.Sprintf("h%d", hostCounter)
				hostCounter++
				spec.Nodes = append(spec.Nodes, TopologyIntentNode{
					ID: hid, Label: hid, Role: "host", Kind: "linux", Image: "ghcr.io/srl-labs/network-multitool:latest",
					X: x0 + float64(li)*dx + float64(hi)*70.0, Y: yHost,
				})
				spec.Links = append(spec.Links, TopologyIntentLink{
					ID: fmt.Sprintf("e%d", linkID),
					A:  hid,
					B:  l,
				})
				linkID++
			}
		}
	} else {
		spec.Assumptions = append(spec.Assumptions, "Prompt did not describe a known fabric shape; generated a starter 2-node topology")
		spec.Nodes = append(spec.Nodes,
			TopologyIntentNode{
				ID: "r1", Label: "r1", Role: "router", Kind: switchKind, Image: switchImage,
				X: 160, Y: 200,
			},
			TopologyIntentNode{
				ID: "r2", Label: "r2", Role: "router", Kind: switchKind, Image: switchImage,
				X: 420, Y: 200,
			},
		)
		spec.Links = append(spec.Links, TopologyIntentLink{
			ID: "e1",
			A:  "r1",
			B:  "r2",
		})
		if req.Hints.IncludeHosts == nil || *req.Hints.IncludeHosts {
			spec.Nodes = append(spec.Nodes, TopologyIntentNode{
				ID: "h1", Label: "h1", Role: "host", Kind: "linux", Image: "ghcr.io/srl-labs/network-multitool:latest",
				X: 290, Y: 380,
			})
			spec.Links = append(spec.Links, TopologyIntentLink{
				ID: "e2",
				A:  "h1",
				B:  "r1",
			})
		}
	}

	for _, marker := range []string{"vpc", "mlag", "sr", "srv6", "mpls"} {
		if strings.Contains(lower, marker) {
			spec.Warnings = append(spec.Warnings, fmt.Sprintf("Detected '%s' intent, but generated only base topology scaffolding", marker))
		}
	}
	sort.Strings(spec.Assumptions)
	sort.Strings(spec.Warnings)
	return spec
}

func renderNetlabYAML(spec TopologyIntentSpec) string {
	var b strings.Builder
	name := strings.TrimSpace(spec.Name)
	if name == "" {
		name = "ai-lab"
	}
	device := strings.TrimSpace(spec.Defaults.Device)
	if device == "" {
		device = "eos"
	}
	b.WriteString("name: " + name + "\n")
	b.WriteString("provider: clab\n")
	b.WriteString("defaults:\n")
	b.WriteString("  device: " + device + "\n")
	b.WriteString("nodes:\n")
	for _, n := range spec.Nodes {
		b.WriteString("  " + n.ID + ":\n")
		if strings.EqualFold(n.Role, "host") || strings.EqualFold(n.Kind, "linux") {
			b.WriteString("    device: linux\n")
		}
	}
	b.WriteString("links:\n")
	for _, l := range spec.Links {
		b.WriteString("  - " + l.A + "-" + l.B + "\n")
	}
	return b.String()
}

func renderContainerlabYAML(spec TopologyIntentSpec) string {
	var b strings.Builder
	name := strings.TrimSpace(spec.Name)
	if name == "" {
		name = "ai-lab"
	}
	b.WriteString("name: " + name + "\n")
	b.WriteString("topology:\n")
	b.WriteString("  nodes:\n")
	for _, n := range spec.Nodes {
		b.WriteString("    " + n.ID + ":\n")
		kind := strings.TrimSpace(n.Kind)
		if kind == "" {
			kind = "linux"
		}
		b.WriteString("      kind: " + kind + "\n")
		if img := strings.TrimSpace(n.Image); img != "" {
			b.WriteString("      image: " + img + "\n")
		}
	}
	b.WriteString("  links:\n")
	ifCounters := map[string]int{}
	for _, l := range spec.Links {
		ifCounters[l.A]++
		ifCounters[l.B]++
		aIf := fmt.Sprintf("eth%d", ifCounters[l.A])
		bIf := fmt.Sprintf("eth%d", ifCounters[l.B])
		b.WriteString(fmt.Sprintf("    - endpoints: [\"%s:%s\", \"%s:%s\"]\n", l.A, aIf, l.B, bIf))
	}
	return b.String()
}

func sanitizeDeploymentName(prompt, fallback string) string {
	base := strings.TrimSpace(prompt)
	if base == "" {
		return fallback
	}
	if len(base) > 48 {
		base = base[:48]
	}
	base = strings.ToLower(base)
	base = regexp.MustCompile(`[^a-z0-9]+`).ReplaceAllString(base, "-")
	base = strings.Trim(base, "-")
	if base == "" {
		return fallback
	}
	return base
}

// GenerateTopologySpecFromPrompt returns a normalized topology intent spec plus deterministic netlab/containerlab YAML renderings.
//
//encore:api auth method=POST path=/api/user/ai/generate-topology-spec
func (s *Service) GenerateTopologySpecFromPrompt(ctx context.Context, req *UserAIGenerateTopologySpecRequest) (*UserAIGenerateTopologySpecResponse, error) {
	_ = ctx
	if _, err := requireAuthUser(); err != nil {
		return nil, err
	}
	if req == nil || strings.TrimSpace(req.Prompt) == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("prompt is required").Err()
	}
	spec := buildSpecFromPrompt(req)
	return &UserAIGenerateTopologySpecResponse{
		Spec:             spec,
		NetlabYAML:       renderNetlabYAML(spec),
		ContainerlabYAML: renderContainerlabYAML(spec),
		GeneratedAt:      time.Now().UTC().Format(time.RFC3339Nano),
	}, nil
}
