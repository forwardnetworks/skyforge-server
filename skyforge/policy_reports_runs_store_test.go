package skyforge

import (
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestPolicyReportsResolveAgg_SuiteScoped(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	mock.ExpectBegin()
	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}

	run := &PolicyReportRun{
		ID:               "run-1",
		UserContextID:    "ws-1",
		ForwardNetworkID: "net-1",
	}
	finishedAt := time.Date(2026, 2, 10, 0, 0, 0, 0, time.UTC)

	checkID := "paths-enforcement-bypass"
	suiteKey := "abc123"

	// Only "keep" is present in this run; "resolve-me" is active but missing -> should be resolved.
	presentByCheck := map[string]map[string]bool{
		checkID: {"keep": true},
	}
	resolveChecks := map[string]policyReportsResolveSpec{
		checkID: {CanResolve: true, SuiteKey: suiteKey},
	}

	mock.ExpectQuery(`(?s)\s*SELECT finding_id.*FROM sf_policy_report_findings_agg.*COALESCE\(finding->>'suiteKey',''\) = \$4`).
		WithArgs(run.UserContextID, run.ForwardNetworkID, checkID, suiteKey).
		WillReturnRows(sqlmock.NewRows([]string{"finding_id"}).AddRow("keep").AddRow("resolve-me"))

	mock.ExpectExec(`(?s)\s*UPDATE sf_policy_report_findings_agg.*COALESCE\(finding->>'suiteKey',''\) = \$7`).
		WithArgs(sqlmock.AnyArg(), run.ID, run.UserContextID, run.ForwardNetworkID, checkID, "resolve-me", suiteKey).
		WillReturnResult(sqlmock.NewResult(0, 1))

	if err := policyReportsResolveAgg(context.Background(), tx, run, finishedAt, presentByCheck, resolveChecks); err != nil {
		t.Fatalf("policyReportsResolveAgg: %v", err)
	}

	mock.ExpectRollback()
	if err := tx.Rollback(); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("ExpectationsWereMet: %v", err)
	}
}
