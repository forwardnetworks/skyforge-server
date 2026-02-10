package skyforge

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"encore.dev/beta/errs"

	"github.com/google/uuid"
)

// NOTE: This file intentionally does not try to replicate Forward's path UI.
// It provides *targeted* read-only "assurance" views that combine a small amount
// of policy intent (e.g., "must traverse enforcement points") with Forward's
// authoritative Paths API.

type PolicyReportPathQuery struct {
	From    string `json:"from,omitempty"`
	SrcIP   string `json:"srcIp,omitempty"`
	DstIP   string `json:"dstIp"`
	IPProto *int   `json:"ipProto,omitempty"`
	DstPort string `json:"dstPort,omitempty"`
	SrcPort string `json:"srcPort,omitempty"`
}

type PolicyReportPathsEnforcementBypassRequest struct {
	ForwardNetworkID string `json:"forwardNetworkId"`
	SnapshotID       string `json:"snapshotId,omitempty"`

	// Flows to evaluate (Path Search bulk).
	Queries []PolicyReportPathQuery `json:"queries"`

	// If true, findings are generated when the computed path doesn't traverse
	// any "enforcement" hop. Default true.
	RequireEnforcement *bool `json:"requireEnforcement,omitempty"`

	// If true, findings are generated when Forward computes a return path and the
	// return path is not DELIVERED (helps detect asymmetric failures). Default false.
	RequireSymmetricDelivery *bool `json:"requireSymmetricDelivery,omitempty"`

	// If true, findings are generated when a return path exists but doesn't traverse
	// any "enforcement" hop. Default false.
	RequireReturnEnforcement *bool `json:"requireReturnEnforcement,omitempty"`

	// "Enforcement" matching rules. If omitted, defaults to firewall-like device types.
	EnforcementDeviceTypes     []string `json:"enforcementDeviceTypes,omitempty"`     // match hop.deviceType
	EnforcementDeviceNameParts []string `json:"enforcementDeviceNameParts,omitempty"` // case-insensitive substring match on hop.deviceName/displayName
	EnforcementTagParts        []string `json:"enforcementTagParts,omitempty"`        // case-insensitive substring match on hop.tags

	// Forward knobs (guardrailed defaults).
	Intent                  string `json:"intent,omitempty"` // default PREFER_DELIVERED
	MaxCandidates           int    `json:"maxCandidates,omitempty"`
	MaxResults              int    `json:"maxResults,omitempty"`
	MaxReturnPathResults    int    `json:"maxReturnPathResults,omitempty"`
	MaxSeconds              int    `json:"maxSeconds,omitempty"`
	MaxOverallSeconds       int    `json:"maxOverallSeconds,omitempty"`
	IncludeTags             *bool  `json:"includeTags,omitempty"`
	IncludeNetworkFunctions *bool  `json:"includeNetworkFunctions,omitempty"`
}

type PolicyReportPathsEnforcementBypassStoreRequest struct {
	ForwardNetworkID string `json:"forwardNetworkId"`
	SnapshotID       string `json:"snapshotId,omitempty"`
	Title            string `json:"title,omitempty"`

	Queries []PolicyReportPathQuery `json:"queries"`

	RequireEnforcement       *bool `json:"requireEnforcement,omitempty"`
	RequireSymmetricDelivery *bool `json:"requireSymmetricDelivery,omitempty"`
	RequireReturnEnforcement *bool `json:"requireReturnEnforcement,omitempty"`

	EnforcementDeviceTypes     []string `json:"enforcementDeviceTypes,omitempty"`
	EnforcementDeviceNameParts []string `json:"enforcementDeviceNameParts,omitempty"`
	EnforcementTagParts        []string `json:"enforcementTagParts,omitempty"`

	Intent                  string `json:"intent,omitempty"`
	MaxCandidates           int    `json:"maxCandidates,omitempty"`
	MaxResults              int    `json:"maxResults,omitempty"`
	MaxReturnPathResults    int    `json:"maxReturnPathResults,omitempty"`
	MaxSeconds              int    `json:"maxSeconds,omitempty"`
	MaxOverallSeconds       int    `json:"maxOverallSeconds,omitempty"`
	IncludeTags             *bool  `json:"includeTags,omitempty"`
	IncludeNetworkFunctions *bool  `json:"includeNetworkFunctions,omitempty"`
}

type PolicyReportPathsEnforcementBypassStoreResponse struct {
	Run     PolicyReportRun                     `json:"run"`
	Checks  []PolicyReportRunCheck              `json:"checks"`
	Results map[string]*PolicyReportNQEResponse `json:"results,omitempty"`
}

type fwdPathSearchQuery struct {
	From    string `json:"from,omitempty"`
	SrcIP   string `json:"srcIp,omitempty"`
	DstIP   string `json:"dstIp"`
	IPProto *int   `json:"ipProto,omitempty"`
	SrcPort string `json:"srcPort,omitempty"`
	DstPort string `json:"dstPort,omitempty"`
}

type fwdPathSearchBulkRequestFull struct {
	Queries []fwdPathSearchQuery `json:"queries"`

	Intent                  string `json:"intent,omitempty"`
	MaxCandidates           int    `json:"maxCandidates,omitempty"`
	MaxResults              int    `json:"maxResults,omitempty"`
	MaxReturnPathResults    int    `json:"maxReturnPathResults,omitempty"`
	MaxSeconds              int    `json:"maxSeconds,omitempty"`
	MaxOverallSeconds       int    `json:"maxOverallSeconds,omitempty"`
	IncludeTags             bool   `json:"includeTags,omitempty"`
	IncludeNetworkFunctions bool   `json:"includeNetworkFunctions,omitempty"`
}

type fwdPathSearchResponseFull struct {
	SrcIPLocationType string        `json:"srcIpLocationType,omitempty"`
	DstIPLocationType string        `json:"dstIpLocationType,omitempty"`
	Info              prFwdPathInfo `json:"info"`
	ReturnPathInfo    prFwdPathInfo `json:"returnPathInfo,omitempty"`
	TimedOut          bool          `json:"timedOut,omitempty"`
	QueryURL          string        `json:"queryUrl,omitempty"`
}

type prFwdPathInfo struct {
	Paths     []prFwdPath `json:"paths"`
	TotalHits int         `json:"totalHits"`
}

type prFwdPath struct {
	ForwardingOutcome string         `json:"forwardingOutcome"`
	SecurityOutcome   string         `json:"securityOutcome"`
	Hops              []prFwdPathHop `json:"hops"`
}

// policyReportsPathsEnforcementBypassEvalFromFwdOut evaluates the suite using a precomputed Forward paths-bulk response.
// It returns the normalized response plus the suite-scoped checkId ("paths-enforcement-bypass:<hash12>").
//
// kept must be the subset of req.Queries that were actually included in the Forward request, in the same order.
func policyReportsPathsEnforcementBypassEvalFromFwdOut(req *PolicyReportPathsEnforcementBypassRequest, kept []PolicyReportPathQuery, fwdOut []fwdPathSearchResponseFull) (*PolicyReportNQEResponse, string, error) {
	if req == nil {
		return nil, "", errs.B().Code(errs.InvalidArgument).Msg("invalid input").Err()
	}
	if strings.TrimSpace(req.ForwardNetworkID) == "" {
		return nil, "", errs.B().Code(errs.InvalidArgument).Msg("forwardNetworkId is required").Err()
	}
	if len(kept) == 0 {
		return &PolicyReportNQEResponse{SnapshotID: strings.TrimSpace(req.SnapshotID), Total: 0, Results: json.RawMessage("[]")}, "", nil
	}

	requireEnf := true
	if req.RequireEnforcement != nil {
		requireEnf = *req.RequireEnforcement
	}
	requireSym := false
	if req.RequireSymmetricDelivery != nil {
		requireSym = *req.RequireSymmetricDelivery
	}
	requireReturnEnf := false
	if req.RequireReturnEnforcement != nil {
		requireReturnEnf = *req.RequireReturnEnforcement
	}

	typeSet := map[string]bool{}
	if len(req.EnforcementDeviceTypes) == 0 {
		typeSet = defaultEnforcementDeviceTypes()
	} else {
		for _, t := range req.EnforcementDeviceTypes {
			t = strings.ToUpper(strings.TrimSpace(t))
			if t != "" {
				typeSet[t] = true
			}
		}
	}
	nameParts := normalizeParts(req.EnforcementDeviceNameParts)
	tagParts := normalizeParts(req.EnforcementTagParts)

	maxReturn := req.MaxReturnPathResults
	if maxReturn < 0 || maxReturn > 10000 {
		maxReturn = 0
	}

	includeTags := true
	if req.IncludeTags != nil {
		includeTags = *req.IncludeTags
	}
	includeNF := true
	if req.IncludeNetworkFunctions != nil {
		includeNF = *req.IncludeNetworkFunctions
	}

	suiteKey := suiteKeyForPathsAssurance(req, kept)
	checkID := "paths-enforcement-bypass:" + suiteKey[:12]

	results := make([]map[string]any, 0, len(kept))
	for i := 0; i < len(kept); i++ {
		q := kept[i]
		out := map[string]any{
			"checkId":   checkID,
			"suiteKey":  suiteKey[:12],
			"category":  "Paths",
			"severity":  "high",
			"assetKey":  strings.TrimSpace(q.SrcIP) + "->" + strings.TrimSpace(q.DstIP),
			"srcIp":     strings.TrimSpace(q.SrcIP),
			"dstIp":     strings.TrimSpace(q.DstIP),
			"ipProto":   q.IPProto,
			"dstPort":   strings.TrimSpace(q.DstPort),
			"intent":    strings.TrimSpace(req.Intent),
			"findingId": findingIDForFlow("paths-enforcement-bypass:"+suiteKey[:12], q),
			"violation": false,
			"riskScore": 0,
			"timedOut":  false,
			"totalHits": 0,
			"queryUrl":  "",
		}

		if i >= len(fwdOut) {
			out["violation"] = true
			out["riskScore"] = 60
			out["error"] = "missing response from Forward"
			results = append(results, out)
			continue
		}

		r := fwdOut[i]
		out["timedOut"] = r.TimedOut
		out["queryUrl"] = strings.TrimSpace(r.QueryURL)
		out["totalHits"] = r.Info.TotalHits

		if r.TimedOut {
			out["violation"] = true
			out["riskScore"] = 60
			out["reason"] = "timed_out"
			results = append(results, out)
			continue
		}
		if len(r.Info.Paths) == 0 {
			out["violation"] = true
			out["riskScore"] = 55
			out["reason"] = "no_paths"
			results = append(results, out)
			continue
		}

		p := r.Info.Paths[0]
		out["forwardingOutcome"] = strings.TrimSpace(p.ForwardingOutcome)
		out["securityOutcome"] = strings.TrimSpace(p.SecurityOutcome)
		out["termination"] = hopTerminationSummary(p.Hops)

		enfHops := []map[string]any{}
		hopsOut := []map[string]any{}
		for _, h := range p.Hops {
			ho := map[string]any{
				"deviceName":       strings.TrimSpace(h.DeviceName),
				"displayName":      strings.TrimSpace(h.DisplayName),
				"deviceType":       strings.TrimSpace(h.DeviceType),
				"ingressInterface": strings.TrimSpace(h.IngressInterface),
				"egressInterface":  strings.TrimSpace(h.EgressInterface),
				"parseError":       h.ParseError,
				"backfilledFrom":   strings.TrimSpace(h.BackfilledFrom),
				"behaviors":        h.Behaviors,
			}
			if includeTags {
				ho["tags"] = h.Tags
			}
			if includeNF && len(h.NetworkFunctions.ACL) > 0 {
				ho["acl"] = h.NetworkFunctions.ACL
			}
			hopsOut = append(hopsOut, ho)

			if hopIsEnforcement(h, typeSet, nameParts, tagParts) {
				enfHops = append(enfHops, ho)
			}
		}
		out["hops"] = hopsOut
		out["enforcementHops"] = enfHops
		out["enforced"] = len(enfHops) > 0
		if includeNF {
			if denied := firstDeniedACL(p.Hops); denied != nil {
				out["deniedAt"] = denied
			}
		}

		if maxReturn > 0 && len(r.ReturnPathInfo.Paths) > 0 {
			rp := r.ReturnPathInfo.Paths[0]
			out["returnForwardingOutcome"] = rp.ForwardingOutcome
			out["returnSecurityOutcome"] = rp.SecurityOutcome
			out["returnTermination"] = hopTerminationSummary(rp.Hops)

			retEnfHops := []map[string]any{}
			retHopsOut := []map[string]any{}
			for _, h := range rp.Hops {
				ho := map[string]any{
					"deviceName":       strings.TrimSpace(h.DeviceName),
					"displayName":      strings.TrimSpace(h.DisplayName),
					"deviceType":       strings.TrimSpace(h.DeviceType),
					"ingressInterface": strings.TrimSpace(h.IngressInterface),
					"egressInterface":  strings.TrimSpace(h.EgressInterface),
					"parseError":       h.ParseError,
					"backfilledFrom":   strings.TrimSpace(h.BackfilledFrom),
					"behaviors":        h.Behaviors,
				}
				if includeTags {
					ho["tags"] = h.Tags
				}
				if includeNF && len(h.NetworkFunctions.ACL) > 0 {
					ho["acl"] = h.NetworkFunctions.ACL
				}
				retHopsOut = append(retHopsOut, ho)
				if hopIsEnforcement(h, typeSet, nameParts, tagParts) {
					retEnfHops = append(retEnfHops, ho)
				}
			}
			out["returnHops"] = retHopsOut
			out["returnEnforcementHops"] = retEnfHops
			out["returnEnforced"] = len(retEnfHops) > 0

			asym := strings.TrimSpace(p.ForwardingOutcome) != strings.TrimSpace(rp.ForwardingOutcome) ||
				strings.TrimSpace(p.SecurityOutcome) != strings.TrimSpace(rp.SecurityOutcome)
			out["asymmetric"] = asym

			if includeNF {
				if denied := firstDeniedACL(rp.Hops); denied != nil {
					out["returnDeniedAt"] = denied
				}
			}
		}

		violation := false
		reasons := []string{}
		score := 0
		if strings.TrimSpace(p.ForwardingOutcome) != "DELIVERED" {
			violation = true
			reasons = append(reasons, "forwarding_outcome:"+strings.TrimSpace(p.ForwardingOutcome))
			score = 80
		}
		if requireEnf && len(enfHops) == 0 {
			violation = true
			reasons = append(reasons, "missing_enforcement")
			if score < 70 {
				score = 70
			}
		}
		if maxReturn > 0 && requireSym {
			if v, ok := out["returnForwardingOutcome"].(string); ok && strings.TrimSpace(v) != "" && strings.TrimSpace(v) != "DELIVERED" {
				violation = true
				reasons = append(reasons, "return_forwarding_outcome:"+strings.TrimSpace(v))
				if score < 75 {
					score = 75
				}
			}
		}
		if maxReturn > 0 && requireReturnEnf {
			if enforced, ok := out["returnEnforced"].(bool); ok && !enforced {
				violation = true
				reasons = append(reasons, "missing_return_enforcement")
				if score < 70 {
					score = 70
				}
			}
		}
		out["violation"] = violation
		out["riskScore"] = score
		if len(reasons) > 0 {
			out["riskReasons"] = reasons
		}

		results = append(results, out)
	}

	b, _ := json.Marshal(results)
	total := 0
	for _, r := range results {
		if v, ok := r["violation"].(bool); ok && v {
			total++
		}
	}

	return &PolicyReportNQEResponse{
		SnapshotID: strings.TrimSpace(req.SnapshotID),
		Total:      total,
		Results:    b,
	}, checkID, nil
}

// policyReportsPathsEnforcementBypassEvalWithClient evaluates the suite using the provided Forward client.
// It returns the normalized response plus the suite-scoped checkId ("paths-enforcement-bypass:<hash12>").
func policyReportsPathsEnforcementBypassEvalWithClient(ctx context.Context, client *forwardClient, req *PolicyReportPathsEnforcementBypassRequest) (*PolicyReportNQEResponse, string, error) {
	if client == nil || req == nil {
		return nil, "", errs.B().Code(errs.InvalidArgument).Msg("invalid input").Err()
	}
	networkID := strings.TrimSpace(req.ForwardNetworkID)
	if networkID == "" {
		return nil, "", errs.B().Code(errs.InvalidArgument).Msg("forwardNetworkId is required").Err()
	}
	if len(req.Queries) == 0 {
		return &PolicyReportNQEResponse{SnapshotID: strings.TrimSpace(req.SnapshotID), Total: 0, Results: json.RawMessage("[]")}, "", nil
	}

	intent := strings.TrimSpace(req.Intent)
	if intent == "" {
		intent = "PREFER_DELIVERED"
	}
	maxCandidates := req.MaxCandidates
	if maxCandidates <= 0 || maxCandidates > 10000 {
		maxCandidates = 5000
	}
	maxResults := req.MaxResults
	if maxResults <= 0 || maxResults > maxCandidates {
		maxResults = 1
	}
	maxReturn := req.MaxReturnPathResults
	if maxReturn < 0 || maxReturn > 10000 {
		maxReturn = 0
	}
	maxSeconds := req.MaxSeconds
	if maxSeconds <= 0 || maxSeconds > 300 {
		maxSeconds = 30
	}
	maxOverall := req.MaxOverallSeconds
	if maxOverall <= 0 || maxOverall > 600 {
		maxOverall = 300
	}
	includeTags := true
	if req.IncludeTags != nil {
		includeTags = *req.IncludeTags
	}
	includeNF := true
	if req.IncludeNetworkFunctions != nil {
		includeNF = *req.IncludeNetworkFunctions
	}

	payload := &fwdPathSearchBulkRequestFull{
		Queries: make([]fwdPathSearchQuery, 0, len(req.Queries)),

		Intent:                  intent,
		MaxCandidates:           maxCandidates,
		MaxResults:              maxResults,
		MaxReturnPathResults:    maxReturn,
		MaxSeconds:              maxSeconds,
		MaxOverallSeconds:       maxOverall,
		IncludeTags:             includeTags,
		IncludeNetworkFunctions: includeNF,
	}
	kept := make([]PolicyReportPathQuery, 0, len(req.Queries))
	for _, q := range req.Queries {
		dst := strings.TrimSpace(q.DstIP)
		if dst == "" {
			continue
		}
		kept = append(kept, q)
		payload.Queries = append(payload.Queries, fwdPathSearchQuery{
			From:    strings.TrimSpace(q.From),
			SrcIP:   strings.TrimSpace(q.SrcIP),
			DstIP:   dst,
			IPProto: q.IPProto,
			SrcPort: strings.TrimSpace(q.SrcPort),
			DstPort: strings.TrimSpace(q.DstPort),
		})
	}
	if len(payload.Queries) == 0 {
		return &PolicyReportNQEResponse{SnapshotID: strings.TrimSpace(req.SnapshotID), Total: 0, Results: json.RawMessage("[]")}, "", nil
	}

	query := url.Values{}
	if v := strings.TrimSpace(req.SnapshotID); v != "" {
		query.Set("snapshotId", v)
	}
	rawPath := forwardAPIPathFor(client, "/networks/"+url.PathEscape(networkID)+"/paths-bulk")

	resp, body, err := client.doJSON(ctx, http.MethodPost, rawPath, query, payload)
	if err != nil {
		return nil, "", errs.B().Code(errs.Unavailable).Msg("Forward request failed").Err()
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, "", errs.B().Code(errs.Unavailable).Msg("Forward paths failed").Meta("upstream", strings.TrimSpace(string(body))).Err()
	}

	var fwdOut []fwdPathSearchResponseFull
	if err := json.Unmarshal(body, &fwdOut); err != nil {
		return nil, "", errs.B().Code(errs.Unavailable).Msg("failed to decode Forward paths response").Err()
	}
	return policyReportsPathsEnforcementBypassEvalFromFwdOut(req, kept, fwdOut)
}

type prFwdPathHop struct {
	DeviceName       string                `json:"deviceName,omitempty"`
	DisplayName      string                `json:"displayName,omitempty"`
	DeviceType       string                `json:"deviceType,omitempty"`
	Tags             []string              `json:"tags,omitempty"`
	ParseError       bool                  `json:"parseError,omitempty"`
	IngressInterface string                `json:"ingressInterface,omitempty"`
	EgressInterface  string                `json:"egressInterface,omitempty"`
	Behaviors        []string              `json:"behaviors,omitempty"`
	NetworkFunctions prFwdNetworkFunctions `json:"networkFunctions,omitempty"`
	BackfilledFrom   string                `json:"backfilledFrom,omitempty"`
}

type prFwdNetworkFunctions struct {
	ACL []prFwdAclFunction `json:"acl,omitempty"`
}

type prFwdAclFunction struct {
	Name    string `json:"name,omitempty"`
	Context string `json:"context,omitempty"`
	Action  string `json:"action,omitempty"`
}

func forwardAPIPathFor(client *forwardClient, pathNoAPIPrefix string) string {
	pathNoAPIPrefix = strings.TrimSpace(pathNoAPIPrefix)
	if pathNoAPIPrefix == "" {
		return ""
	}
	if strings.HasPrefix(pathNoAPIPrefix, "/api/") {
		// already full
		return pathNoAPIPrefix
	}
	base := strings.TrimRight(strings.TrimSpace(client.baseURL), "/")
	if strings.HasSuffix(strings.ToLower(base), "/api") {
		return pathNoAPIPrefix
	}
	if strings.HasPrefix(pathNoAPIPrefix, "/") {
		return "/api" + pathNoAPIPrefix
	}
	return "/api/" + pathNoAPIPrefix
}

func defaultEnforcementDeviceTypes() map[string]bool {
	// Keep this conservative: only explicit firewall-ish nodes.
	types := []string{
		"FIREWALL",
		"AWS_NETWORK_FIREWALL",
		"AZURE_FIREWALL",
		"AZURE_VIRTUAL_APPLIANCE",
	}
	out := map[string]bool{}
	for _, t := range types {
		out[t] = true
	}
	return out
}

func normalizeParts(ss []string) []string {
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		s = strings.ToLower(strings.TrimSpace(s))
		if s == "" {
			continue
		}
		out = append(out, s)
	}
	return out
}

func hopIsEnforcement(h prFwdPathHop, typeSet map[string]bool, nameParts, tagParts []string) bool {
	if typeSet != nil {
		if typeSet[strings.ToUpper(strings.TrimSpace(h.DeviceType))] {
			return true
		}
	}
	nameHay := strings.ToLower(strings.TrimSpace(h.DeviceName + " " + h.DisplayName))
	for _, p := range nameParts {
		if p != "" && strings.Contains(nameHay, p) {
			return true
		}
	}
	if len(tagParts) > 0 && len(h.Tags) > 0 {
		for _, t := range h.Tags {
			tl := strings.ToLower(strings.TrimSpace(t))
			for _, p := range tagParts {
				if p != "" && strings.Contains(tl, p) {
					return true
				}
			}
		}
	}
	return false
}

func hopTerminationSummary(hops []prFwdPathHop) map[string]any {
	if len(hops) == 0 {
		return nil
	}
	h := hops[len(hops)-1]
	out := map[string]any{
		"deviceName":  strings.TrimSpace(h.DeviceName),
		"displayName": strings.TrimSpace(h.DisplayName),
		"deviceType":  strings.TrimSpace(h.DeviceType),
	}
	if h.ParseError {
		out["parseError"] = true
	}
	if v := strings.TrimSpace(h.BackfilledFrom); v != "" {
		out["backfilledFrom"] = v
	}
	return out
}

func firstDeniedACL(hops []prFwdPathHop) map[string]any {
	for _, h := range hops {
		for _, fn := range h.NetworkFunctions.ACL {
			act := strings.ToUpper(strings.TrimSpace(fn.Action))
			if act == "DENY" || act == "DROP" || act == "REJECT" {
				return map[string]any{
					"deviceName":  strings.TrimSpace(h.DeviceName),
					"displayName": strings.TrimSpace(h.DisplayName),
					"deviceType":  strings.TrimSpace(h.DeviceType),
					"name":        strings.TrimSpace(fn.Name),
					"context":     strings.TrimSpace(fn.Context),
					"action":      strings.TrimSpace(fn.Action),
				}
			}
		}
	}
	return nil
}

func findingIDForFlow(prefix string, q PolicyReportPathQuery) string {
	h := sha256.Sum256([]byte(strings.Join([]string{
		strings.TrimSpace(prefix),
		strings.TrimSpace(q.From),
		strings.TrimSpace(q.SrcIP),
		strings.TrimSpace(q.DstIP),
		strings.TrimSpace(q.SrcPort),
		strings.TrimSpace(q.DstPort),
		func() string {
			if q.IPProto == nil {
				return ""
			}
			return strconv.Itoa(*q.IPProto)
		}(),
	}, "|")))
	return hex.EncodeToString(h[:])
}

func suiteKeyForPathsAssurance(req *PolicyReportPathsEnforcementBypassRequest, kept []PolicyReportPathQuery) string {
	if req == nil {
		return ""
	}
	lines := make([]string, 0, len(kept))
	for _, q := range kept {
		src := strings.TrimSpace(q.SrcIP)
		dst := strings.TrimSpace(q.DstIP)
		ipProto := ""
		if q.IPProto != nil {
			ipProto = strconv.Itoa(*q.IPProto)
		}
		lines = append(lines, strings.Join([]string{
			strings.TrimSpace(q.From),
			src,
			dst,
			strings.TrimSpace(q.SrcPort),
			strings.TrimSpace(q.DstPort),
			ipProto,
		}, "|"))
	}
	sort.Strings(lines)

	requireEnf := "true"
	if req.RequireEnforcement != nil && !*req.RequireEnforcement {
		requireEnf = "false"
	}
	requireSym := "false"
	if req.RequireSymmetricDelivery != nil && *req.RequireSymmetricDelivery {
		requireSym = "true"
	}
	requireRetEnf := "false"
	if req.RequireReturnEnforcement != nil && *req.RequireReturnEnforcement {
		requireRetEnf = "true"
	}

	intent := strings.TrimSpace(req.Intent)
	if intent == "" {
		intent = "PREFER_DELIVERED"
	}

	parts := []string{
		"requireEnf=" + requireEnf,
		"requireSym=" + requireSym,
		"requireRetEnf=" + requireRetEnf,
		"intent=" + strings.ToUpper(intent),
		"types=" + strings.Join(normalizeParts(req.EnforcementDeviceTypes), ","),
		"nameParts=" + strings.Join(normalizeParts(req.EnforcementDeviceNameParts), ","),
		"tagParts=" + strings.Join(normalizeParts(req.EnforcementTagParts), ","),
		"queries=" + strings.Join(lines, "\n"),
	}

	h := sha256.Sum256([]byte(strings.Join(parts, "\n")))
	return hex.EncodeToString(h[:])
}

// PostWorkspacePolicyReportPathsEnforcementBypass evaluates a set of flows and returns
// violation-style findings when traffic doesn't traverse enforcement points.
//
// This is meant to highlight a core Forward advantage: authoritative path computation.
// It complements NQE policy analytics by showing when traffic can bypass expected controls
// due to routing/topology changes or missing collectors.
//
//encore:api auth method=POST path=/api/workspaces/:id/policy-reports/paths/enforcement-bypass
func (s *Service) PostWorkspacePolicyReportPathsEnforcementBypass(ctx context.Context, id string, req *PolicyReportPathsEnforcementBypassRequest) (*PolicyReportNQEResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.workspaceContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("request required").Err()
	}
	networkID := strings.TrimSpace(req.ForwardNetworkID)
	if networkID == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("forwardNetworkId is required").Err()
	}
	if len(req.Queries) == 0 {
		return &PolicyReportNQEResponse{SnapshotID: strings.TrimSpace(req.SnapshotID), Total: 0, Results: json.RawMessage("[]")}, nil
	}

	client, err := s.policyReportsForwardClient(ctx, pc.workspace.ID, pc.claims.Username, networkID)
	if err != nil {
		return nil, err
	}

	out, _, err := policyReportsPathsEnforcementBypassEvalWithClient(ctx, client, req)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// PostWorkspacePolicyReportPathsEnforcementBypassStore runs Paths Assurance and persists it as a Policy Report run.
//
// This is intentionally a thin wrapper around the live Paths endpoint so the UI can:
// - schedule it (via presets later, if desired)
// - trend it via stored runs and ACTIVE/RESOLVED findings
//
//encore:api auth method=POST path=/api/workspaces/:id/policy-reports/paths/enforcement-bypass/store
func (s *Service) PostWorkspacePolicyReportPathsEnforcementBypassStore(ctx context.Context, id string, req *PolicyReportPathsEnforcementBypassStoreRequest) (*PolicyReportPathsEnforcementBypassStoreResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.workspaceContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if err := requireWorkspaceEditor(pc); err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("db not configured").Err()
	}
	if req == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("request required").Err()
	}

	networkID := strings.TrimSpace(req.ForwardNetworkID)
	if networkID == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("forwardNetworkId is required").Err()
	}
	if len(req.Queries) == 0 {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("queries are required").Err()
	}

	// Normalize into the live endpoint request type.
	live := &PolicyReportPathsEnforcementBypassRequest{
		ForwardNetworkID:           networkID,
		SnapshotID:                 strings.TrimSpace(req.SnapshotID),
		Queries:                    req.Queries,
		RequireEnforcement:         req.RequireEnforcement,
		RequireSymmetricDelivery:   req.RequireSymmetricDelivery,
		RequireReturnEnforcement:   req.RequireReturnEnforcement,
		EnforcementDeviceTypes:     req.EnforcementDeviceTypes,
		EnforcementDeviceNameParts: req.EnforcementDeviceNameParts,
		EnforcementTagParts:        req.EnforcementTagParts,
		Intent:                     req.Intent,
		MaxCandidates:              req.MaxCandidates,
		MaxResults:                 req.MaxResults,
		MaxReturnPathResults:       req.MaxReturnPathResults,
		MaxSeconds:                 req.MaxSeconds,
		MaxOverallSeconds:          req.MaxOverallSeconds,
		IncludeTags:                req.IncludeTags,
		IncludeNetworkFunctions:    req.IncludeNetworkFunctions,
	}

	startedAt := time.Now().UTC()
	client, err := s.policyReportsForwardClient(ctx, pc.workspace.ID, pc.claims.Username, networkID)
	if err != nil {
		return nil, err
	}
	resp, checkID, err := policyReportsPathsEnforcementBypassEvalWithClient(ctx, client, live)
	if err != nil {
		return nil, err
	}
	finishedAt := time.Now().UTC()
	if strings.TrimSpace(checkID) == "" {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to compute suite check id").Err()
	}

	violations, _ := policyReportsExtractViolationFindings(checkID, resp)

	runTitle := strings.TrimSpace(req.Title)
	if runTitle == "" {
		runTitle = "Paths Assurance"
	}
	reqJSON, _ := json.Marshal(req)
	run := PolicyReportRun{
		ID:               uuid.New().String(),
		WorkspaceID:      pc.workspace.ID,
		ForwardNetworkID: networkID,
		SnapshotID:       strings.TrimSpace(req.SnapshotID),
		PackID:           "paths-assurance",
		Title:            runTitle,
		Status:           "SUCCEEDED",
		CreatedBy:        strings.ToLower(strings.TrimSpace(pc.claims.Username)),
		StartedAt:        startedAt,
		FinishedAt:       &finishedAt,
		Request:          reqJSON,
	}

	checks := []PolicyReportRunCheck{{
		RunID:   run.ID,
		CheckID: checkID,
		Total:   0,
	}}
	if resp != nil {
		checks[0].Total = resp.Total
	}

	findings := make([]PolicyReportRunFinding, 0, len(violations))
	for _, v := range violations {
		findings = append(findings, PolicyReportRunFinding{
			RunID:     run.ID,
			CheckID:   checkID,
			FindingID: v.FindingID,
			RiskScore: v.RiskScore,
			AssetKey:  v.AssetKey,
			Finding:   v.Finding,
		})
	}

	resolveChecks := map[string]bool{checkID: true}
	if err := persistPolicyReportRun(ctx, s.db, &run, checks, findings, resolveChecks); err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to persist run").Err()
	}

	results := map[string]*PolicyReportNQEResponse{checkID: resp}
	return &PolicyReportPathsEnforcementBypassStoreResponse{
		Run:     run,
		Checks:  checks,
		Results: results,
	}, nil
}
