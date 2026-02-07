package skyforge

import "testing"

func TestLoadPolicyReportCatalog(t *testing.T) {
	cat, err := loadPolicyReportCatalog()
	if err != nil {
		t.Fatalf("loadPolicyReportCatalog: %v", err)
	}
	if cat == nil {
		t.Fatalf("catalog is nil")
	}
	if cat.Version == "" {
		t.Fatalf("catalog version is empty")
	}
	if len(cat.Checks) == 0 {
		t.Fatalf("catalog checks is empty")
	}
}

func TestPolicyReportsListNQEFiles(t *testing.T) {
	files, err := policyReportsListNQEFiles()
	if err != nil {
		t.Fatalf("policyReportsListNQEFiles: %v", err)
	}
	if len(files) == 0 {
		t.Fatalf("expected embedded .nqe files")
	}
	found := false
	for _, f := range files {
		if f == "acl-any-any-permit.nqe" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected acl-any-any-permit.nqe in embedded files")
	}
}

func TestPolicyReportsNormalizeNQEResponse(t *testing.T) {
	body := []byte(`{
  "snapshotId": "S-1",
  "totalNumItems": 3,
  "items": [{"k": 1}]
}`)
	out, err := policyReportsNormalizeNQEResponse(body)
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if out.SnapshotID != "S-1" {
		t.Fatalf("snapshotId: got %q", out.SnapshotID)
	}
	if out.Total != 3 {
		t.Fatalf("total: got %d", out.Total)
	}
}
