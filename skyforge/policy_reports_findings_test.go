package skyforge

import (
	"encoding/json"
	"testing"
)

func TestPolicyReportsComputeFindingID_IsStableAcrossKeyOrder(t *testing.T) {
	// Same logical object, different key order.
	a := json.RawMessage(`{"device":"fw1","rule":"permit web","ruleIndex":12,"action":"PERMIT"}`)
	b := json.RawMessage(`{"action":"PERMIT","ruleIndex":12,"rule":"permit web","device":"fw1"}`)

	ida := policyReportsComputeFindingID("acl-flow-to-rules.nqe", a)
	idb := policyReportsComputeFindingID("acl-flow-to-rules.nqe", b)
	if ida != idb {
		t.Fatalf("expected stable findingId; got %q vs %q", ida, idb)
	}
}

func TestPolicyReportsAugmentResultsWithFindingIDs_InjectsFindingId(t *testing.T) {
	results := json.RawMessage(`[
	  {"device":"fw1","rule":"r1","ruleIndex":1},
	  {"device":"fw1","rule":"r2","ruleIndex":2}
	]`)
	aug, err := policyReportsAugmentResults("acl-flow-to-rules.nqe", results)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var arr []map[string]any
	if err := json.Unmarshal(aug, &arr); err != nil {
		t.Fatalf("unexpected json: %v", err)
	}
	if len(arr) != 2 {
		t.Fatalf("expected 2 items, got %d", len(arr))
	}
	for i, it := range arr {
		v, ok := it["findingId"]
		if !ok {
			t.Fatalf("missing findingId at index %d", i)
		}
		s, _ := v.(string)
		if s == "" {
			t.Fatalf("empty findingId at index %d", i)
		}
	}
}

func TestPolicyReportsAugmentResults_IncludesRiskFields(t *testing.T) {
	results := json.RawMessage(`[
	  {"device":"fw1","rule":"r1","ruleIndex":1,"ipv4Src":["0.0.0.0/0"],"ipv4Dst":["10.0.0.0/8"],"tpDst":[]}
	]`)
	aug, err := policyReportsAugmentResults("acl-any-any-permit.nqe", results)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var arr []map[string]any
	if err := json.Unmarshal(aug, &arr); err != nil {
		t.Fatalf("unexpected json: %v", err)
	}
	if len(arr) != 1 {
		t.Fatalf("expected 1 item, got %d", len(arr))
	}
	if _, ok := arr[0]["riskScore"]; !ok {
		t.Fatalf("missing riskScore")
	}
	if _, ok := arr[0]["riskReasons"]; !ok {
		t.Fatalf("missing riskReasons")
	}
}

func TestPolicyReportsAugmentResults_DoesNotOverwriteExistingRiskReasons(t *testing.T) {
	results := json.RawMessage(`[
	  {"checkId":"paths-enforcement-bypass","suiteKey":"abc123","violation":true,"severity":"high","riskReasons":["missing_enforcement"]}
	]`)
	aug, err := policyReportsAugmentResults("paths-enforcement-bypass", results)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var arr []map[string]any
	if err := json.Unmarshal(aug, &arr); err != nil {
		t.Fatalf("unexpected json: %v", err)
	}
	if len(arr) != 1 {
		t.Fatalf("expected 1 item, got %d", len(arr))
	}
	if _, ok := arr[0]["riskScore"]; !ok {
		t.Fatalf("missing riskScore")
	}
	reasons, ok := arr[0]["riskReasons"].([]any)
	if !ok || len(reasons) != 1 {
		t.Fatalf("expected 1 riskReasons item, got %#v", arr[0]["riskReasons"])
	}
	if s, _ := reasons[0].(string); s != "missing_enforcement" {
		t.Fatalf("expected preserved riskReasons, got %#v", arr[0]["riskReasons"])
	}
}
