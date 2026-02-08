package skyforge

import (
	"testing"
	"time"
)

func TestNormalizeElasticIndexingMode(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", "instance"},
		{"instance", "instance"},
		{"INSTANCE", "instance"},
		{"per_user", "per_user"},
		{"per-user", "per_user"},
		{"peruser", "per_user"},
		{"nope", "instance"},
	}
	for _, tc := range cases {
		if got := normalizeElasticIndexingMode(tc.in); got != tc.want {
			t.Fatalf("normalizeElasticIndexingMode(%q)=%q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestSanitizeElasticUserComponent(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"  ", ""},
		{"Alice", "alice"},
		{"ALICE", "alice"},
		{"a.b_c", "a-b-c"},
		{"a/b\\c", "a-b-c"},
		{"---", "user"},
		{"..__..", "user"},
		{"bob@example.com", "bob-example-com"},
	}
	for _, tc := range cases {
		if got := sanitizeElasticUserComponent(tc.in); got != tc.want {
			t.Fatalf("sanitizeElasticUserComponent(%q)=%q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestShouldElasticToolsSleep(t *testing.T) {
	now := time.Date(2026, 2, 8, 12, 0, 0, 0, time.UTC)
	if shouldElasticToolsSleep(time.Time{}, 30*time.Minute, now) {
		t.Fatalf("expected zero lastActivity to never sleep")
	}
	if shouldElasticToolsSleep(now.Add(-10*time.Minute), 30*time.Minute, now) {
		t.Fatalf("expected 10m idle to not sleep with 30m timeout")
	}
	if !shouldElasticToolsSleep(now.Add(-31*time.Minute), 30*time.Minute, now) {
		t.Fatalf("expected 31m idle to sleep with 30m timeout")
	}
}
