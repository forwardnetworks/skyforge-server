package skyforge

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestUserScopeAliasTarget(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		url  string
		want string
	}{
		{
			name: "workspace root",
			url:  "/api/user/workspace",
			want: "/api/workspaces/me/",
		},
		{
			name: "workspace child",
			url:  "/api/user/workspace/deployments",
			want: "/api/workspaces/me/deployments",
		},
		{
			name: "scope root",
			url:  "/api/user/scope",
			want: "/api/workspaces/me/",
		},
		{
			name: "scope child",
			url:  "/api/user/scope/deployments",
			want: "/api/workspaces/me/deployments",
		},
		{
			name: "scope with query",
			url:  "/api/user/scope/deployments?limit=10",
			want: "/api/workspaces/me/deployments?limit=10",
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest("GET", tc.url, nil)
			got := userScopeAliasTarget(req)
			if got != tc.want {
				t.Fatalf("unexpected target: got %q want %q", got, tc.want)
			}
		})
	}
}

func TestDeprecatedUserScopeAliasHeaders(t *testing.T) {
	t.Parallel()
	svc := &Service{}
	req := httptest.NewRequest(http.MethodGet, "/api/user/scope/deployments?limit=5", nil)
	rr := httptest.NewRecorder()
	svc.UserScopeAlias(rr, req)
	resp := rr.Result()
	if resp.StatusCode != http.StatusTemporaryRedirect {
		t.Fatalf("unexpected status: got %d want %d", resp.StatusCode, http.StatusTemporaryRedirect)
	}
	if got := resp.Header.Get("Deprecation"); got != "true" {
		t.Fatalf("unexpected deprecation header: got %q want %q", got, "true")
	}
	if got := resp.Header.Get("Sunset"); got == "" {
		t.Fatalf("missing Sunset header")
	}
	if got := resp.Header.Get("Location"); got != "/api/workspaces/me/deployments?limit=5" {
		t.Fatalf("unexpected redirect location: got %q", got)
	}
}
