package skyforge

import "testing"

func TestTrackOwnerRouteUsage(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name           string
		in             string
		wantLegacy     bool
		wantNormalized string
	}{
		{
			name:           "empty uses personal",
			in:             "",
			wantLegacy:     false,
			wantNormalized: "me",
		},
		{
			name:           "me alias",
			in:             "me",
			wantLegacy:     false,
			wantNormalized: "me",
		},
		{
			name:           "self alias",
			in:             "self",
			wantLegacy:     false,
			wantNormalized: "self",
		},
		{
			name:           "scope id legacy",
			in:             "ws-123",
			wantLegacy:     true,
			wantNormalized: "ws-123",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			legacy, normalized := trackOwnerRouteUsage(tt.in)
			if legacy != tt.wantLegacy {
				t.Fatalf("legacy mismatch: got %v want %v", legacy, tt.wantLegacy)
			}
			if normalized != tt.wantNormalized {
				t.Fatalf("normalized mismatch: got %q want %q", normalized, tt.wantNormalized)
			}
		})
	}
}

func TestOwnerStrictModeEnabled(t *testing.T) {
	t.Setenv("SKYFORGE_OWNER_ROUTES_STRICT", "")
	if !ownerStrictModeEnabled() {
		t.Fatalf("expected strict mode enabled by default")
	}

	t.Setenv("SKYFORGE_OWNER_ROUTES_STRICT", "true")
	if !ownerStrictModeEnabled() {
		t.Fatalf("expected strict mode enabled for true")
	}

	t.Setenv("SKYFORGE_OWNER_ROUTES_STRICT", "1")
	if !ownerStrictModeEnabled() {
		t.Fatalf("expected strict mode enabled for 1")
	}

	t.Setenv("SKYFORGE_OWNER_ROUTES_STRICT", "false")
	if !ownerStrictModeEnabled() {
		t.Fatalf("expected strict mode enabled even when false is set")
	}

	t.Setenv("SKYFORGE_OWNER_ROUTES_STRICT", "no")
	if !ownerStrictModeEnabled() {
		t.Fatalf("expected strict mode enabled even when no is set")
	}
}
