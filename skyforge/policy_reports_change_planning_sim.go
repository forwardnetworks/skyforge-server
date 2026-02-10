package skyforge

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// policyReportsFlowToRulesItem is the minimal result shape returned by acl-flow-to-rules.nqe
// that we need for change-planning simulation.
type policyReportsFlowToRulesItem struct {
	Device    string `json:"device"`
	RuleIndex int    `json:"ruleIndex"`
	Rule      string `json:"rule"`
	Action    string `json:"action"`
}

type policyReportsDecision struct {
	Decision string
	Rule     string
	Index    int
}

func policyReportsFirstMatchDecision(matches []policyReportsFlowToRulesItem) policyReportsDecision {
	if len(matches) == 0 {
		return policyReportsDecision{Decision: "NO_MATCH", Rule: "", Index: -1}
	}
	first := matches[0]
	return policyReportsDecision{
		Decision: normalizePolicyAction(first.Action),
		Rule:     strings.TrimSpace(first.Rule),
		Index:    first.RuleIndex,
	}
}

func policyReportsDecisionChanged(before, after policyReportsDecision) bool {
	return before.Decision != after.Decision || before.Rule != after.Rule || before.Index != after.Index
}

func normalizePolicyAction(v string) string {
	s := strings.ToUpper(strings.TrimSpace(v))
	switch s {
	case "PERMIT", "ALLOW":
		return "PERMIT"
	case "DENY", "DROP", "REJECT":
		return "DENY"
	case "":
		return "UNKNOWN"
	default:
		return s
	}
}

func normalizePolicyReportFlowTuple(in PolicyReportFlowTuple) (PolicyReportFlowTuple, error) {
	out := in
	out.SrcIP = strings.TrimSpace(out.SrcIP)
	out.DstIP = strings.TrimSpace(out.DstIP)
	if out.SrcIP == "" || out.DstIP == "" {
		return PolicyReportFlowTuple{}, fmt.Errorf("flow srcIp and dstIp are required")
	}
	// UI often passes -1 for "ignore"; if omitted in JSON it may come through as 0.
	if out.IPProto == 0 {
		out.IPProto = -1
	}
	if out.DstPort == 0 {
		out.DstPort = -1
	}
	return out, nil
}

func policyReportsSimulateAfterDecision(flow PolicyReportFlowTuple, matches []policyReportsFlowToRulesItem, change PolicyReportRuleChange) (policyReportsDecision, string) {
	op := strings.ToUpper(strings.TrimSpace(change.Op))
	if op == "" {
		op = "ADD"
	}
	switch op {
	case "ADD":
		return policyReportsSimulateAdd(flow, matches, change.Rule)
	case "REMOVE":
		return policyReportsSimulateRemove(flow, matches, change.Rule)
	case "MODIFY":
		return policyReportsSimulateModify(flow, matches, change.Rule)
	default:
		// Should be validated by caller.
		return policyReportsFirstMatchDecision(matches), "unsupported op"
	}
}

func policyReportsSimulateAdd(flow PolicyReportFlowTuple, matches []policyReportsFlowToRulesItem, rule PolicyReportProposedRule) (policyReportsDecision, string) {
	before := policyReportsFirstMatchDecision(matches)

	// ADD shifts indices >= inserted index.
	shiftIndex := func(idx int) int {
		if idx < 0 {
			return idx
		}
		if idx >= rule.Index {
			return idx + 1
		}
		return idx
	}

	if !policyReportsProposedRuleMatchesFlow(rule, flow) {
		after := before
		after.Index = shiftIndex(after.Index)
		if before.Index != after.Index {
			return after, "added rule does not match; indices shifted"
		}
		return after, "added rule does not match"
	}

	// If there was no match before, or the insertion is before/at the first match,
	// the added rule becomes the effective decision.
	if before.Index < 0 || rule.Index <= before.Index {
		return policyReportsDecision{
			Decision: normalizePolicyAction(rule.Action),
			Rule:     "(added rule)",
			Index:    rule.Index,
		}, "added rule matches and becomes first match"
	}

	after := before
	after.Index = shiftIndex(after.Index)
	if before.Index != after.Index {
		return after, "added rule matches but is after first match; indices shifted"
	}
	return after, "added rule matches but is after first match"
}

func policyReportsSimulateRemove(flow PolicyReportFlowTuple, matches []policyReportsFlowToRulesItem, rule PolicyReportProposedRule) (policyReportsDecision, string) {
	before := policyReportsFirstMatchDecision(matches)

	// REMOVE shifts indices > removed index.
	shiftIndex := func(idx int) int {
		if idx < 0 {
			return idx
		}
		if idx > rule.Index {
			return idx - 1
		}
		return idx
	}

	// If the removed rule was the first match, after becomes the next matching rule (if any).
	if before.Index == rule.Index && before.Index >= 0 {
		for _, it := range matches {
			if it.RuleIndex <= rule.Index {
				continue
			}
			return policyReportsDecision{
				Decision: normalizePolicyAction(it.Action),
				Rule:     strings.TrimSpace(it.Rule),
				Index:    shiftIndex(it.RuleIndex),
			}, "removed first match; next match becomes effective"
		}
		return policyReportsDecision{Decision: "NO_MATCH", Rule: "", Index: -1}, "removed first match; no remaining matches"
	}

	after := before
	after.Index = shiftIndex(after.Index)
	if before.Index != after.Index {
		return after, "removed rule; indices shifted"
	}
	return after, "removed rule does not affect first match"
}

func policyReportsSimulateModify(flow PolicyReportFlowTuple, matches []policyReportsFlowToRulesItem, rule PolicyReportProposedRule) (policyReportsDecision, string) {
	before := policyReportsFirstMatchDecision(matches)

	modIdx := rule.Index
	modMatches := policyReportsProposedRuleMatchesFlow(rule, flow)

	// Find the earliest unchanged match with index < modIdx.
	for _, it := range matches {
		if it.RuleIndex < modIdx {
			return policyReportsDecision{
				Decision: normalizePolicyAction(it.Action),
				Rule:     strings.TrimSpace(it.Rule),
				Index:    it.RuleIndex,
			}, "modified rule is after the effective decision"
		}
		break
	}

	// If the modified rule now matches, it becomes first match (since no earlier matches exist).
	if modMatches {
		afterRule := "(modified rule)"
		// If we have a name for the rule at that index (from before matches), keep it.
		for _, it := range matches {
			if it.RuleIndex == modIdx && strings.TrimSpace(it.Rule) != "" {
				afterRule = strings.TrimSpace(it.Rule)
				break
			}
			if it.RuleIndex > modIdx {
				break
			}
		}
		after := policyReportsDecision{
			Decision: normalizePolicyAction(rule.Action),
			Rule:     afterRule,
			Index:    modIdx,
		}
		if before.Index == modIdx && before.Decision != after.Decision {
			return after, "modified first match; action changed"
		}
		if before.Index == modIdx && before.Decision == after.Decision {
			return after, "modified first match; still matches"
		}
		return after, "modified rule now matches and becomes first match"
	}

	// Modified rule does not match; choose the next unchanged matching rule with index > modIdx.
	for _, it := range matches {
		if it.RuleIndex <= modIdx {
			continue
		}
		return policyReportsDecision{
			Decision: normalizePolicyAction(it.Action),
			Rule:     strings.TrimSpace(it.Rule),
			Index:    it.RuleIndex,
		}, "modified rule no longer matches; next match becomes effective"
	}
	return policyReportsDecision{Decision: "NO_MATCH", Rule: "", Index: -1}, "modified rule does not match; no remaining matches"
}

func policyReportsProposedRuleMatchesFlow(rule PolicyReportProposedRule, flow PolicyReportFlowTuple) bool {
	src := net.ParseIP(strings.TrimSpace(flow.SrcIP))
	dst := net.ParseIP(strings.TrimSpace(flow.DstIP))
	if src == nil || dst == nil {
		return false
	}
	if !policyReportsIPInSubnets(src, rule.Ipv4Src) {
		return false
	}
	if !policyReportsIPInSubnets(dst, rule.Ipv4Dst) {
		return false
	}

	if flow.IPProto >= 0 && len(rule.IPProto) > 0 {
		found := false
		for _, p := range rule.IPProto {
			if p == flow.IPProto {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	if flow.DstPort >= 0 && len(rule.TpDst) > 0 {
		ok := false
		for _, r := range rule.TpDst {
			lo, hi, okRange := policyReportsParsePortRange(strings.TrimSpace(r))
			if !okRange {
				continue
			}
			if lo <= flow.DstPort && flow.DstPort <= hi {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}

	return true
}

func policyReportsParsePortRange(s string) (int, int, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, 0, false
	}
	// Accept "443" or "443-445".
	if strings.Contains(s, "-") {
		parts := strings.SplitN(s, "-", 2)
		if len(parts) != 2 {
			return 0, 0, false
		}
		lo, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
		hi, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err1 != nil || err2 != nil {
			return 0, 0, false
		}
		if lo <= 0 || hi <= 0 || lo > 65535 || hi > 65535 {
			return 0, 0, false
		}
		if hi < lo {
			lo, hi = hi, lo
		}
		return lo, hi, true
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, 0, false
	}
	if n <= 0 || n > 65535 {
		return 0, 0, false
	}
	return n, n, true
}

func policyReportsIPInSubnets(ip net.IP, subnets []string) bool {
	if len(subnets) == 0 {
		return true
	}
	for _, raw := range subnets {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		if strings.Contains(s, "/") {
			_, cidr, err := net.ParseCIDR(s)
			if err == nil && cidr != nil && cidr.Contains(ip) {
				return true
			}
			continue
		}
		// Treat plain IP as /32.
		needle := net.ParseIP(s)
		if needle != nil && needle.Equal(ip) {
			return true
		}
	}
	return false
}
