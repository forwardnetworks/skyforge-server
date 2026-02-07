package skyforge

import (
	"net/netip"
	"strconv"
	"strings"
)

func toString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case []byte:
		return string(t)
	default:
		return ""
	}
}

func toInt(v any) int {
	switch t := v.(type) {
	case int:
		return t
	case int32:
		return int(t)
	case int64:
		return int(t)
	case float64:
		return int(t)
	case string:
		n, _ := strconv.Atoi(strings.TrimSpace(t))
		return n
	default:
		return 0
	}
}

func firstMatchDecision(matches []map[string]any, skipIndex int) (decision string, rule string, idx int) {
	for _, it := range matches {
		i := toInt(it["ruleIndex"])
		if skipIndex >= 0 && i == skipIndex {
			continue
		}
		act := strings.TrimSpace(toString(it["action"]))
		name := strings.TrimSpace(toString(it["rule"]))
		if act == "" {
			act = "UNKNOWN"
		}
		return act, name, i
	}
	return "NO_MATCH", "", -1
}

type intRange struct {
	start int
	end   int
}

func parseRanges(spec []string) ([]intRange, bool) {
	if len(spec) == 0 {
		return nil, true
	}
	var out []intRange
	for _, s := range spec {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if strings.Contains(s, "-") {
			parts := strings.SplitN(s, "-", 2)
			a, errA := strconv.Atoi(strings.TrimSpace(parts[0]))
			b, errB := strconv.Atoi(strings.TrimSpace(parts[1]))
			if errA != nil || errB != nil {
				continue
			}
			if a > b {
				a, b = b, a
			}
			out = append(out, intRange{start: a, end: b})
			continue
		}
		n, err := strconv.Atoi(s)
		if err != nil {
			continue
		}
		out = append(out, intRange{start: n, end: n})
	}
	if len(out) == 0 {
		return nil, false
	}
	return out, true
}

func cidrContainsAny(cidrList []string, ip netip.Addr) bool {
	if len(cidrList) == 0 {
		return true
	}
	okAny := false
	for _, s := range cidrList {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		p, err := netip.ParsePrefix(s)
		if err != nil {
			continue
		}
		okAny = true
		if p.Contains(ip) {
			return true
		}
	}
	// If user provided CIDRs but none parsed, treat as non-match.
	return !okAny
}

func intListContains(list []int, v int) bool {
	if len(list) == 0 {
		return true
	}
	for _, it := range list {
		if it == v {
			return true
		}
	}
	return false
}

func rangesContain(ranges []intRange, v int) bool {
	if len(ranges) == 0 {
		return true
	}
	for _, r := range ranges {
		if r.start <= v && v <= r.end {
			return true
		}
	}
	return false
}

func proposedRuleMatchesFlow(rule PolicyReportProposedRule, flow PolicyReportFlowTuple) bool {
	src, err := netip.ParseAddr(strings.TrimSpace(flow.SrcIP))
	if err != nil {
		return false
	}
	dst, err := netip.ParseAddr(strings.TrimSpace(flow.DstIP))
	if err != nil {
		return false
	}
	if !cidrContainsAny(rule.Ipv4Src, src) {
		return false
	}
	if !cidrContainsAny(rule.Ipv4Dst, dst) {
		return false
	}
	if flow.IPProto >= 0 && !intListContains(rule.IPProto, flow.IPProto) {
		return false
	}
	if flow.DstPort >= 0 {
		ranges, ok := parseRanges(rule.TpDst)
		if !ok {
			return false
		}
		if !rangesContain(ranges, flow.DstPort) {
			return false
		}
	}
	return true
}

func normalizeAction(action string) string {
	action = strings.ToUpper(strings.TrimSpace(action))
	switch action {
	case "PERMIT", "DENY":
		return action
	default:
		if action == "" {
			return "UNKNOWN"
		}
		return action
	}
}

func simulateChangeDecision(op string, rule PolicyReportProposedRule, flow PolicyReportFlowTuple, matches []map[string]any) (afterDecision, afterRule string, afterIdx int, reason string) {
	beforeDecision, beforeRule, beforeIdx := firstMatchDecision(matches, -1)
	_ = beforeDecision
	_ = beforeRule
	_ = beforeIdx

	op = strings.ToUpper(strings.TrimSpace(op))
	ruleIdx := rule.Index
	ruleAction := normalizeAction(rule.Action)

	switch op {
	case "ADD":
		matchesNew := proposedRuleMatchesFlow(rule, flow)
		if !matchesNew {
			d, r, i := firstMatchDecision(matches, -1)
			return d, r, i, "proposed-rule-no-match"
		}
		d, r, i := firstMatchDecision(matches, -1)
		if i < 0 || ruleIdx <= i {
			return ruleAction, "PROPOSED_RULE", ruleIdx, "inserted-before-first-match"
		}
		return d, r, i, "inserted-after-first-match"

	case "REMOVE":
		d, r, i := firstMatchDecision(matches, -1)
		if i == ruleIdx {
			d2, r2, i2 := firstMatchDecision(matches, ruleIdx)
			return d2, r2, i2, "removed-first-match"
		}
		return d, r, i, "removed-non-first-match"

	case "MODIFY":
		// Conceptually: remove the old rule at ruleIdx and replace it with the proposed one.
		modMatches := proposedRuleMatchesFlow(rule, flow)
		// Existing first match after removing the rule at ruleIdx.
		dRem, rRem, iRem := firstMatchDecision(matches, ruleIdx)
		// If there is an earlier rule than ruleIdx that already matches, it still wins.
		earlierD, earlierR, earlierI := firstMatchDecision(matches, -1)
		if earlierI >= 0 && earlierI < ruleIdx {
			return earlierD, earlierR, earlierI, "earlier-rule-still-matches"
		}
		if modMatches && (iRem < 0 || ruleIdx <= iRem) {
			return ruleAction, "PROPOSED_RULE", ruleIdx, "modified-rule-wins"
		}
		if iRem < 0 {
			return "NO_MATCH", "", -1, "modified-rule-no-match"
		}
		return dRem, rRem, iRem, "next-rule-wins"

	default:
		d, r, i := firstMatchDecision(matches, -1)
		return d, r, i, "no-op"
	}
}

