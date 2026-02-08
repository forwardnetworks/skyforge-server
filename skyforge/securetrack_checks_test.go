package skyforge

import "testing"

func TestLoadSecureTrackCatalog(t *testing.T) {
	cat, err := loadSecureTrackCatalog()
	if err != nil {
		t.Fatalf("loadSecureTrackCatalog: %v", err)
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

func TestSecureTrackListNQEFiles(t *testing.T) {
	files, err := secureTrackListNQEFiles()
	if err != nil {
		t.Fatalf("secureTrackListNQEFiles: %v", err)
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

func TestSecureTrackNormalizeNQEResponse(t *testing.T) {
	body := []byte(`{
  "snapshotId": "S-1",
  "totalNumItems": 3,
  "items": [{"k": 1}]
}`)
	out, err := secureTrackNormalizeNQEResponse(body)
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
