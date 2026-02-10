package skyforge

import "testing"

func TestPolicyReportsParsePortRange(t *testing.T) {
	cases := []struct {
		in     string
		wantLo int
		wantHi int
		wantOK bool
	}{
		{"443", 443, 443, true},
		{"443-445", 443, 445, true},
		{"445-443", 443, 445, true},
		{"0", 0, 0, false},
		{"65536", 0, 0, false},
		{"", 0, 0, false},
		{"abc", 0, 0, false},
	}
	for _, tc := range cases {
		lo, hi, ok := policyReportsParsePortRange(tc.in)
		if ok != tc.wantOK || lo != tc.wantLo || hi != tc.wantHi {
			t.Fatalf("parse(%q) = (%d,%d,%v) want (%d,%d,%v)", tc.in, lo, hi, ok, tc.wantLo, tc.wantHi, tc.wantOK)
		}
	}
}

func TestPolicyReportsProposedRuleMatchesFlow(t *testing.T) {
	flow := PolicyReportFlowTuple{SrcIP: "10.0.0.1", DstIP: "10.1.2.3", IPProto: 6, DstPort: 443}

	// Any-any-any should match.
	if !policyReportsProposedRuleMatchesFlow(PolicyReportProposedRule{Index: 0, Action: "PERMIT"}, flow) {
		t.Fatalf("expected any-any to match")
	}

	// CIDR match.
	r1 := PolicyReportProposedRule{Index: 0, Action: "PERMIT", Ipv4Src: []string{"10.0.0.0/24"}, Ipv4Dst: []string{"10.1.0.0/16"}, IPProto: []int{6}, TpDst: []string{"443"}}
	if !policyReportsProposedRuleMatchesFlow(r1, flow) {
		t.Fatalf("expected cidr+proto+port to match")
	}

	// Wrong dst port range.
	r2 := PolicyReportProposedRule{Index: 0, Action: "PERMIT", TpDst: []string{"80"}}
	if policyReportsProposedRuleMatchesFlow(r2, flow) {
		t.Fatalf("expected port mismatch")
	}
}

func TestPolicyReportsSimulateAdd(t *testing.T) {
	flow := PolicyReportFlowTuple{SrcIP: "10.0.0.1", DstIP: "10.1.2.3", IPProto: 6, DstPort: 443}
	matches := []policyReportsFlowToRulesItem{
		{Device: "fw1", RuleIndex: 10, Rule: "R10", Action: "PERMIT"},
		{Device: "fw1", RuleIndex: 20, Rule: "R20", Action: "DENY"},
	}

	after, _ := policyReportsSimulateAdd(flow, matches, PolicyReportProposedRule{Index: 5, Action: "DENY"})
	if after.Decision != "DENY" || after.Index != 5 {
		t.Fatalf("expected added rule to become first match, got %+v", after)
	}
}

func TestPolicyReportsSimulateRemoveFirstMatch(t *testing.T) {
	flow := PolicyReportFlowTuple{SrcIP: "10.0.0.1", DstIP: "10.1.2.3", IPProto: 6, DstPort: 443}
	matches := []policyReportsFlowToRulesItem{
		{Device: "fw1", RuleIndex: 1, Rule: "R1", Action: "PERMIT"},
		{Device: "fw1", RuleIndex: 3, Rule: "R3", Action: "DENY"},
	}

	after, _ := policyReportsSimulateRemove(flow, matches, PolicyReportProposedRule{Index: 1})
	if after.Decision != "DENY" || after.Index != 2 {
		t.Fatalf("expected next match (shifted) after removal, got %+v", after)
	}
}
