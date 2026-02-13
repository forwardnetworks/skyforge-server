package skyforge

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRewriteForwardOnPremRedirectLocation_RelativeLogin(t *testing.T) {
	got := rewriteForwardOnPremRedirectLocation("/login", "skyforge.local.forwardnetworks.com", "https", false)
	want := "/fwd/login"
	if got != want {
		t.Fatalf("unexpected rewrite: got %q want %q", got, want)
	}
}

func TestRewriteForwardOnPremRedirectLocation_RelativeRoot(t *testing.T) {
	got := rewriteForwardOnPremRedirectLocation("/", "skyforge.local.forwardnetworks.com", "https", false)
	want := "/fwd/login"
	if got != want {
		t.Fatalf("unexpected rewrite: got %q want %q", got, want)
	}
}

func TestRewriteForwardOnPremRedirectLocation_InternalAbsoluteRoot(t *testing.T) {
	got := rewriteForwardOnPremRedirectLocation(
		"https://fwd-appserver.forward.svc.cluster.local:8443/",
		"skyforge.local.forwardnetworks.com",
		"https",
		false,
	)
	want := "https://skyforge.local.forwardnetworks.com/fwd/login"
	if got != want {
		t.Fatalf("unexpected rewrite: got %q want %q", got, want)
	}
}

func TestRewriteForwardOnPremRedirectLocation_ExternalAbsoluteRoot(t *testing.T) {
	got := rewriteForwardOnPremRedirectLocation(
		"https://skyforge.local.forwardnetworks.com/",
		"skyforge.local.forwardnetworks.com",
		"https",
		false,
	)
	want := "https://skyforge.local.forwardnetworks.com/fwd/login"
	if got != want {
		t.Fatalf("unexpected rewrite: got %q want %q", got, want)
	}
}

func TestRewriteForwardOnPremRedirectLocation_ExternalUnrelated(t *testing.T) {
	in := "https://example.com/login"
	got := rewriteForwardOnPremRedirectLocation(in, "skyforge.local.forwardnetworks.com", "https", false)
	if got != in {
		t.Fatalf("unexpected rewrite: got %q want unchanged %q", got, in)
	}
}

func TestRewriteForwardOnPremRedirectLocation_RootAliasesLogin(t *testing.T) {
	got := rewriteForwardOnPremRedirectLocation("/login", "skyforge.local.forwardnetworks.com", "https", true)
	if got != "/login" {
		t.Fatalf("unexpected rewrite: got %q want /login", got)
	}
}

func TestRewriteForwardOnPremSetCookiePathsPrefixMode(t *testing.T) {
	resp := &http.Response{Header: http.Header{}}
	resp.Header.Add("Set-Cookie", "SESSION=abc; Path=/; Secure; HttpOnly")
	resp.Header.Add("Set-Cookie", "TOKEN=xyz; Secure")

	rewriteForwardOnPremSetCookiePaths(resp, "prefix")

	got := resp.Header.Values("Set-Cookie")
	if len(got) != 2 {
		t.Fatalf("expected 2 set-cookie values, got %d", len(got))
	}
	if got[0] != "SESSION=abc; Path=/fwd; Secure; HttpOnly" {
		t.Fatalf("unexpected first cookie rewrite: %q", got[0])
	}
	if got[1] != "TOKEN=xyz; Secure; Path=/fwd" {
		t.Fatalf("unexpected second cookie rewrite: %q", got[1])
	}
}

func TestRewriteForwardOnPremSetCookiePathsAliasMode(t *testing.T) {
	resp := &http.Response{Header: http.Header{}}
	resp.Header.Add("Set-Cookie", "SESSION=abc; Path=/; Secure; HttpOnly")

	rewriteForwardOnPremSetCookiePaths(resp, "alias")

	got := resp.Header.Values("Set-Cookie")
	if len(got) != 1 {
		t.Fatalf("expected 1 set-cookie value, got %d", len(got))
	}
	if got[0] != "SESSION=abc; Path=/; Secure; HttpOnly" {
		t.Fatalf("unexpected cookie rewrite in alias mode: %q", got[0])
	}
}

func TestSanitizeForwardOnPremCookies(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://skyforge.local.forwardnetworks.com/fwd/login", nil)
	req.Header.Set("Cookie", "SKYFORGE_SESSION=abc; SESSION=def; REDIRECT_URI=ghi; OTHER=jkl")

	sanitizeForwardOnPremCookies(req)

	got := req.Header.Get("Cookie")
	want := "SESSION=def; REDIRECT_URI=ghi; OTHER=jkl"
	if got != want {
		t.Fatalf("unexpected cookie header: got %q want %q", got, want)
	}
}
