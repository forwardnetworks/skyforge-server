package skyforge

import "testing"

func TestTrackWorkspaceRouteUsage(t *testing.T) {
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
			name:           "workspace id legacy",
			in:             "ws-123",
			wantLegacy:     true,
			wantNormalized: "ws-123",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			legacy, normalized := trackWorkspaceRouteUsage(tt.in)
			if legacy != tt.wantLegacy {
				t.Fatalf("legacy mismatch: got %v want %v", legacy, tt.wantLegacy)
			}
			if normalized != tt.wantNormalized {
				t.Fatalf("normalized mismatch: got %q want %q", normalized, tt.wantNormalized)
			}
		})
	}
}

func TestWorkspaceStrictModeEnabled(t *testing.T) {
	t.Setenv("SKYFORGE_WORKSPACE_ROUTES_STRICT", "true")
	if !workspaceStrictModeEnabled() {
		t.Fatalf("expected strict mode enabled for true")
	}

	t.Setenv("SKYFORGE_WORKSPACE_ROUTES_STRICT", "1")
	if !workspaceStrictModeEnabled() {
		t.Fatalf("expected strict mode enabled for 1")
	}

	t.Setenv("SKYFORGE_WORKSPACE_ROUTES_STRICT", "false")
	if workspaceStrictModeEnabled() {
		t.Fatalf("expected strict mode disabled for false")
	}
}
