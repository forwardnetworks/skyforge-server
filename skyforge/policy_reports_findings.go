package skyforge

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
)

// policyReportsComputeFindingID generates a stable identifier for a single NQE result item.
//
// This is used for delta computations and (best-effort) augmentation of results returned
// by Policy Reports checks/packs. The goal is stability across snapshots when the same
// underlying "thing" (e.g., device+rule) is present.
func policyReportsComputeFindingID(checkID string, item json.RawMessage) string {
	key := policyReportsComputeFindingKey(checkID, item)
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

func policyReportsComputeFindingKey(checkID string, item json.RawMessage) string {
	checkID = strings.TrimSpace(checkID)
	// "check=" included so identical rules in different checks don't collide.
	parts := []string{"check=" + strings.ToLower(checkID)}

	var obj map[string]json.RawMessage
	if err := json.Unmarshal(item, &obj); err != nil || obj == nil {
		return strings.Join(append(parts, "raw="+policyReportsHashBytes(item)), "|")
	}

	addStr := func(name string, keys ...string) {
		for _, k := range keys {
			if v := policyReportsGetString(obj, k); v != "" {
				parts = append(parts, name+"="+v)
				return
			}
		}
	}
	addInt := func(name string, keys ...string) {
		for _, k := range keys {
			if v, ok := policyReportsGetInt(obj, k); ok {
				parts = append(parts, name+"="+strconv.Itoa(v))
				return
			}
		}
	}

	// Common identity anchors.
	addStr("device", "device", "Device")

	// "rule" style checks.
	addStr("rule", "rule", "Rule", "shadowedRule", "shadowingRule", "earlierRule", "laterRule", "ruleA", "ruleB", "firstRule")

	// Prefer indices when present.
	addInt("idx", "ruleIndex", "firstRuleIndex", "shadowedRuleIndex", "shadowingRuleIndex", "earlierRuleIndex", "laterRuleIndex", "ruleAIndex", "ruleBIndex")

	// Cloud policy anchors (e.g., AWS SG).
	addStr("cloudAccount", "cloudAccountId", "cloudAccount")
	addStr("vpc", "vpcId", "vpc")
	addStr("sg", "securityGroupId", "securityGroup")

	// Other identifiers used by non-ACL checks.
	addStr("ospfProcess", "ospfProcess")

	// Include the decision/action when present so "flow-decision" can show meaningful deltas.
	addStr("decision", "decision")
	addStr("action", "action")

	if len(parts) == 1 { // only check=...
		return strings.Join(append(parts, "obj="+policyReportsHashBytes(item)), "|")
	}
	return strings.Join(parts, "|")
}

func policyReportsHashBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func policyReportsGetString(obj map[string]json.RawMessage, key string) string {
	raw, ok := obj[key]
	if !ok || len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return strings.TrimSpace(s)
	}
	// Fall back to the raw JSON string, trimmed.
	return strings.TrimSpace(string(raw))
}

func policyReportsGetInt(obj map[string]json.RawMessage, key string) (int, bool) {
	raw, ok := obj[key]
	if !ok || len(raw) == 0 {
		return 0, false
	}
	var n int
	if err := json.Unmarshal(raw, &n); err == nil {
		return n, true
	}
	var f float64
	if err := json.Unmarshal(raw, &f); err == nil {
		return int(f), true
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		s = strings.TrimSpace(s)
		if s == "" {
			return 0, false
		}
		if v, err := strconv.Atoi(s); err == nil {
			return v, true
		}
	}
	return 0, false
}

func policyReportsExtractFindingID(item json.RawMessage) string {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(item, &obj); err != nil || obj == nil {
		return ""
	}
	return policyReportsGetString(obj, "findingId")
}

type policyReportsCheckMeta struct {
	CheckID  string
	Title    string
	Category string
	Severity string
}

func policyReportsLookupCheckMeta(checkID string) policyReportsCheckMeta {
	meta := policyReportsCheckMeta{CheckID: strings.TrimSpace(checkID)}
	cat, err := loadPolicyReportCatalog()
	if err != nil || cat == nil {
		return meta
	}
	idNorm := strings.TrimSpace(checkID)
	if idNorm != "" && !strings.HasSuffix(strings.ToLower(idNorm), ".nqe") {
		idNorm += ".nqe"
	}
	for _, c := range cat.Checks {
		if strings.TrimSpace(c.ID) != idNorm {
			continue
		}
		meta.Title = strings.TrimSpace(c.Title)
		meta.Category = strings.TrimSpace(c.Category)
		meta.Severity = strings.TrimSpace(c.Severity)
		return meta
	}
	return meta
}

func baseRiskScoreFromSeverity(sev string) int {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case "critical":
		return 85
	case "high":
		return 70
	case "medium":
		return 45
	case "low":
		return 20
	default:
		return 35
	}
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func policyReportsArrayLen(obj map[string]json.RawMessage, key string) (int, bool) {
	raw, ok := obj[key]
	if !ok || len(raw) == 0 {
		return 0, false
	}
	var arr []any
	if err := json.Unmarshal(raw, &arr); err == nil {
		return len(arr), true
	}
	return 0, false
}

func policyReportsArrayContainsString(obj map[string]json.RawMessage, key string, needle string) bool {
	raw, ok := obj[key]
	if !ok || len(raw) == 0 {
		return false
	}
	var arr []any
	if err := json.Unmarshal(raw, &arr); err != nil {
		return false
	}
	for _, it := range arr {
		s, ok := it.(string)
		if !ok {
			continue
		}
		if strings.Contains(strings.ToLower(s), strings.ToLower(needle)) {
			return true
		}
	}
	return false
}

func policyReportsComputeRisk(meta policyReportsCheckMeta, obj map[string]json.RawMessage) (int, []string) {
	score := baseRiskScoreFromSeverity(meta.Severity)
	reasons := []string{"base:" + strings.ToLower(strings.TrimSpace(meta.Severity))}

	// Generic heuristics derived from common modeled ACL fields.
	if n, ok := policyReportsArrayLen(obj, "ipv4Src"); ok {
		if n == 0 || policyReportsArrayContainsString(obj, "ipv4Src", "0.0.0.0/0") {
			score += 10
			reasons = append(reasons, "src:any")
		}
	}
	if n, ok := policyReportsArrayLen(obj, "ipv4Dst"); ok {
		if n == 0 || policyReportsArrayContainsString(obj, "ipv4Dst", "0.0.0.0/0") {
			score += 10
			reasons = append(reasons, "dst:any")
		}
	}
	if n, ok := policyReportsArrayLen(obj, "tpDst"); ok && n == 0 {
		score += 10
		reasons = append(reasons, "port:any")
	}
	if n, ok := policyReportsArrayLen(obj, "ipProto"); ok && n == 0 {
		score += 5
		reasons = append(reasons, "proto:any")
	}
	if policyReportsGetString(obj, "reason") == "NO_USAGE_DATA" {
		score += 5
		reasons = append(reasons, "usage:unknown")
	}
	if v, ok := policyReportsGetInt(obj, "hitCount"); ok && v == 0 {
		score += 3
		reasons = append(reasons, "hitCount:0")
	}
	ov := policyReportsGetString(obj, "overApproximated")
	if strings.EqualFold(strings.TrimSpace(ov), "true") {
		score += 10
		reasons = append(reasons, "match:overApproximated")
	}

	return clampInt(score, 0, 100), reasons
}

// policyReportsAugmentResults best-effort injects finding + metadata keys into each JSON object result.
func policyReportsAugmentResults(checkID string, results json.RawMessage) (json.RawMessage, error) {
	if len(results) == 0 {
		return results, nil
	}
	var arr []json.RawMessage
	if err := json.Unmarshal(results, &arr); err != nil {
		return results, nil
	}
	if len(arr) == 0 {
		return results, nil
	}

	meta := policyReportsLookupCheckMeta(checkID)

	out := make([]json.RawMessage, 0, len(arr))
	for _, raw := range arr {
		if len(raw) == 0 {
			continue
		}
		id := policyReportsExtractFindingID(raw)
		if id == "" {
			id = policyReportsComputeFindingID(checkID, raw)
		}
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(raw, &obj); err == nil && obj != nil {
			if _, ok := obj["findingId"]; !ok {
				b, _ := json.Marshal(id)
				obj["findingId"] = b
			}
			if _, ok := obj["checkId"]; !ok && meta.CheckID != "" {
				b, _ := json.Marshal(strings.TrimSpace(checkID))
				obj["checkId"] = b
			}
			if _, ok := obj["checkTitle"]; !ok && meta.Title != "" {
				b, _ := json.Marshal(meta.Title)
				obj["checkTitle"] = b
			}
			if _, ok := obj["category"]; !ok && meta.Category != "" {
				b, _ := json.Marshal(meta.Category)
				obj["category"] = b
			}
			if _, ok := obj["severity"]; !ok && meta.Severity != "" {
				b, _ := json.Marshal(meta.Severity)
				obj["severity"] = b
			}
			if _, ok := obj["riskScore"]; !ok {
				score, reasons := policyReportsComputeRisk(meta, obj)
				b, _ := json.Marshal(score)
				obj["riskScore"] = b
				rb, _ := json.Marshal(reasons)
				obj["riskReasons"] = rb
			}
			nb, err := json.Marshal(obj)
			if err == nil {
				out = append(out, nb)
				continue
			}
		}
		out = append(out, raw)
	}

	nb, err := json.Marshal(out)
	if err != nil {
		return results, nil
	}
	return nb, nil
}

// policyReportsCanonicalJSONHash returns a stable hash of JSON content with some keys removed.
// Used for delta "changed" detection where map key ordering must not affect equality.
func policyReportsCanonicalJSONHash(raw json.RawMessage, ignoreKeys map[string]bool) string {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return policyReportsHashBytes(raw)
	}
	canon := policyReportsCanonicalize(v, ignoreKeys)
	b, err := json.Marshal(canon)
	if err != nil {
		return policyReportsHashBytes(raw)
	}
	return policyReportsHashBytes(b)
}

func policyReportsCanonicalize(v any, ignoreKeys map[string]bool) any {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			if ignoreKeys != nil && ignoreKeys[k] {
				continue
			}
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out := make([]any, 0, len(keys))
		for _, k := range keys {
			out = append(out, []any{k, policyReportsCanonicalize(t[k], ignoreKeys)})
		}
		return out
	case []any:
		out := make([]any, 0, len(t))
		for _, it := range t {
			out = append(out, policyReportsCanonicalize(it, ignoreKeys))
		}
		return out
	default:
		return v
	}
}
