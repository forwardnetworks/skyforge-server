package taskengine

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testForwardClient(t *testing.T, server *httptest.Server) *forwardClient {
	t.Helper()
	return &forwardClient{
		baseURL:  strings.TrimRight(server.URL, "/"),
		username: "user",
		password: "pass",
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

func readBody(t *testing.T, r *http.Request) map[string]any {
	t.Helper()
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	defer r.Body.Close()
	out := map[string]any{}
	if len(raw) == 0 {
		return out
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal body: %v", err)
	}
	return out
}

func TestForwardEnableSNMPPerfCollectionPatchSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/networks/net-1/performance/settings" {
			http.NotFound(w, r)
			return
		}
		u, p, ok := r.BasicAuth()
		if !ok || u != "user" || p != "pass" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodPatch {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body := readBody(t, r)
		if v, ok := body["enabled"].(bool); !ok || !v {
			http.Error(w, "bad payload", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := testForwardClient(t, server)
	if err := forwardEnableSNMPPerfCollection(context.Background(), client, "net-1"); err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
}

func TestForwardEnableSNMPPerfCollectionMethodOnlyPatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/networks/net-2/performance/settings" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodPatch {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body := readBody(t, r)
		if v, ok := body["enabled"].(bool); !ok || !v {
			http.Error(w, "bad payload", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := testForwardClient(t, server)
	if err := forwardEnableSNMPPerfCollection(context.Background(), client, "net-2"); err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
}

func TestForwardEnableSNMPPerfCollectionFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/networks/net-3/performance/settings" {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "invalid payload", http.StatusBadRequest)
	}))
	defer server.Close()

	client := testForwardClient(t, server)
	err := forwardEnableSNMPPerfCollection(context.Background(), client, "net-3")
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "forward performance settings update failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}
