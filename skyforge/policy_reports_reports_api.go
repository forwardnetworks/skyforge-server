package skyforge

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"encore.dev/beta/errs"
)

type PolicyReportRunReportRequest struct {
	Format string `query:"format" encore:"optional"` // markdown (default)
	Limit  int    `query:"limit" encore:"optional"`  // max findings to include (default 200)
}

type PolicyReportRunReportResponse struct {
	Format  string `json:"format"`
	Content string `json:"content"`
}

// GetWorkspacePolicyReportRunReport renders a stored run into an auditor-friendly report.
//
//encore:api auth method=GET path=/api/workspaces/:id/policy-reports/runs/:runId/report
func (s *Service) GetWorkspacePolicyReportRunReport(ctx context.Context, id string, runId string, req *PolicyReportRunReportRequest) (*PolicyReportRunReportResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.workspaceContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("db not configured").Err()
	}

	format := "markdown"
	limit := 200
	if req != nil {
		if v := strings.ToLower(strings.TrimSpace(req.Format)); v != "" {
			format = v
		}
		if req.Limit > 0 && req.Limit <= 2000 {
			limit = req.Limit
		}
	}
	if format != "markdown" && format != "md" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("unsupported format").Err()
	}

	run, checks, err := getPolicyReportRun(ctx, s.db, pc.workspace.ID, runId)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errs.B().Code(errs.NotFound).Msg("run not found").Err()
		}
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load run").Err()
	}

	findings, err := listPolicyReportRunFindings(ctx, s.db, pc.workspace.ID, runId, "", limit)
	if err != nil && !isMissingDBRelation(err) {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load run findings").Err()
	}

	md := policyReportsRenderRunMarkdown(*run, checks, findings)
	return &PolicyReportRunReportResponse{Format: "markdown", Content: md}, nil
}

func policyReportsRenderRunMarkdown(run PolicyReportRun, checks []PolicyReportRunCheck, findings []PolicyReportRunFinding) string {
	title := strings.TrimSpace(run.Title)
	if title == "" {
		title = strings.TrimSpace(run.PackID)
	}

	var b strings.Builder
	b.WriteString("# Policy Report\n\n")
	b.WriteString(fmt.Sprintf("**Title:** %s\n\n", escapeMD(title)))
	b.WriteString(fmt.Sprintf("**Run ID:** `%s`\n\n", escapeMD(run.ID)))
	b.WriteString(fmt.Sprintf("**Forward Network:** `%s`\n\n", escapeMD(run.ForwardNetworkID)))
	b.WriteString(fmt.Sprintf("**Snapshot:** `%s`\n\n", escapeMD(func() string {
		if strings.TrimSpace(run.SnapshotID) == "" {
			return "latest"
		}
		return run.SnapshotID
	}())))
	b.WriteString(fmt.Sprintf("**Pack:** `%s`\n\n", escapeMD(run.PackID)))
	b.WriteString(fmt.Sprintf("**Status:** `%s`\n\n", escapeMD(run.Status)))
	if strings.TrimSpace(run.Error) != "" {
		b.WriteString(fmt.Sprintf("**Error:** %s\n\n", escapeMD(run.Error)))
	}
	b.WriteString(fmt.Sprintf("**Started:** %s\n\n", run.StartedAt.UTC().Format(time.RFC3339)))
	if run.FinishedAt != nil {
		b.WriteString(fmt.Sprintf("**Finished:** %s\n\n", run.FinishedAt.UTC().Format(time.RFC3339)))
	}

	// Checks summary.
	b.WriteString("## Checks\n\n")
	b.WriteString("| Check | Total |\n| --- | ---: |\n")
	sort.Slice(checks, func(i, j int) bool { return checks[i].CheckID < checks[j].CheckID })
	for _, c := range checks {
		b.WriteString(fmt.Sprintf("| `%s` | %d |\n", escapeMD(strings.TrimSpace(c.CheckID)), c.Total))
	}
	b.WriteString("\n")

	// Findings summary.
	if len(findings) == 0 {
		b.WriteString("## Findings\n\nNo stored violation findings for this run.\n")
		return b.String()
	}

	b.WriteString("## Findings (Top)\n\n")
	b.WriteString("| Risk | Check | Asset | Finding ID |\n| ---: | --- | --- | --- |\n")
	for _, f := range findings {
		b.WriteString(fmt.Sprintf("| %d | `%s` | `%s` | `%s` |\n",
			f.RiskScore,
			escapeMD(strings.TrimSpace(f.CheckID)),
			escapeMD(strings.TrimSpace(f.AssetKey)),
			escapeMD(strings.TrimSpace(f.FindingID)),
		))
	}
	b.WriteString("\n")

	// Include a compact JSON snippet per finding to keep reports self-contained.
	b.WriteString("## Finding Details (JSON)\n\n")
	for _, f := range findings {
		b.WriteString(fmt.Sprintf("### %s\n\n", escapeMD(f.FindingID)))
		b.WriteString(fmt.Sprintf("- Check: `%s`\n", escapeMD(f.CheckID)))
		if strings.TrimSpace(f.AssetKey) != "" {
			b.WriteString(fmt.Sprintf("- Asset: `%s`\n", escapeMD(f.AssetKey)))
		}
		b.WriteString(fmt.Sprintf("- Risk: `%d`\n\n", f.RiskScore))

		raw := strings.TrimSpace(string(f.Finding))
		if raw == "" {
			raw = "{}"
		} else {
			// pretty print if possible
			var v any
			if err := json.Unmarshal([]byte(raw), &v); err == nil {
				if pb, err := json.MarshalIndent(v, "", "  "); err == nil {
					raw = string(pb)
				}
			}
		}
		b.WriteString("```json\n")
		b.WriteString(raw)
		b.WriteString("\n```\n\n")
	}

	return b.String()
}

func escapeMD(s string) string {
	// Minimal escaping to avoid table breaks.
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	return strings.TrimSpace(s)
}
