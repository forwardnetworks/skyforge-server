package skyforge

type PolicyReportFlowTuple struct {
	SrcIP   string `json:"srcIp"`
	DstIP   string `json:"dstIp"`
	IPProto int    `json:"ipProto,omitempty"`
	DstPort int    `json:"dstPort,omitempty"`
}

type PolicyReportProposedRule struct {
	Index   int      `json:"index"`
	Action  string   `json:"action"`            // PERMIT or DENY
	Ipv4Src []string `json:"ipv4Src,omitempty"` // CIDR strings, empty = any
	Ipv4Dst []string `json:"ipv4Dst,omitempty"`
	IPProto []int    `json:"ipProto,omitempty"` // empty = any
	TpDst   []string `json:"tpDst,omitempty"`   // entries like "443" or "443-445"; empty = any
}

type PolicyReportRuleChange struct {
	Op   string                   `json:"op"` // ADD, REMOVE, MODIFY
	Rule PolicyReportProposedRule `json:"rule"`
}

type PolicyReportChangePlanningRequest struct {
	NetworkID              string                  `json:"networkId"`
	SnapshotID             string                  `json:"snapshotId,omitempty"`
	FirewallsOnly          bool                    `json:"firewallsOnly,omitempty"`
	IncludeImplicitDefault bool                    `json:"includeImplicitDefault,omitempty"`
	DeviceName             string                  `json:"deviceName,omitempty"` // optional filter
	Flows                  []PolicyReportFlowTuple `json:"flows"`
	Change                 PolicyReportRuleChange  `json:"change"`
}

type PolicyReportFlowImpact struct {
	Device         string                `json:"device"`
	Flow           PolicyReportFlowTuple `json:"flow"`
	BeforeDecision string                `json:"beforeDecision"`
	AfterDecision  string                `json:"afterDecision"`
	BeforeRule     string                `json:"beforeRule,omitempty"`
	AfterRule      string                `json:"afterRule,omitempty"`
	BeforeIndex    int                   `json:"beforeIndex,omitempty"`
	AfterIndex     int                   `json:"afterIndex,omitempty"`
	Changed        bool                  `json:"changed"`
	Reason         string                `json:"reason,omitempty"`
}

type PolicyReportChangePlanningResponse struct {
	TotalFlows   int                      `json:"totalFlows"`
	TotalDevices int                      `json:"totalDevices"`
	ChangedCount int                      `json:"changedCount"`
	Impacts      []PolicyReportFlowImpact `json:"impacts"`
}
