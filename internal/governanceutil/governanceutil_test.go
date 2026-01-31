package governanceutil

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestIntervalString(t *testing.T) {
	t.Parallel()
	if got := IntervalString(0); got != "0 seconds" {
		t.Fatalf("expected 0 seconds, got %q", got)
	}
	if got := IntervalString(1500 * time.Millisecond); got != "1 seconds" {
		t.Fatalf("expected 1 seconds, got %q", got)
	}
	if got := IntervalString(10 * time.Second); got != "10 seconds" {
		t.Fatalf("expected 10 seconds, got %q", got)
	}
}

func TestPercentile(t *testing.T) {
	t.Parallel()
	if got := Percentile(nil, 0.95); got != 0 {
		t.Fatalf("expected 0 for empty input, got %v", got)
	}
	values := []float64{10, 20, 30, 40}
	if got := Percentile(values, 0); got != 10 {
		t.Fatalf("p0 expected 10, got %v", got)
	}
	if got := Percentile(values, 1); got != 40 {
		t.Fatalf("p100 expected 40, got %v", got)
	}
	if got := Percentile(values, 0.5); got != 20 {
		t.Fatalf("p50 expected nearest-rank=20, got %v", got)
	}
	if got := Percentile(values, 0.95); got != 40 {
		t.Fatalf("p95 expected 40, got %v", got)
	}
}

func TestCollectInventoryCountsWithRequest_Pagination(t *testing.T) {
	t.Parallel()

	type listResponse[T any] struct {
		Items    []T `json:"items"`
		Metadata struct {
			Continue string `json:"continue"`
		} `json:"metadata"`
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/namespaces":
			cont := r.URL.Query().Get("continue")
			if cont == "" {
				resp := listResponse[struct {
					Metadata struct {
						Name string `json:"name"`
					} `json:"metadata"`
				}]{
					Items: []struct {
						Metadata struct {
							Name string `json:"name"`
						} `json:"metadata"`
					}{
						{Metadata: struct {
							Name string `json:"name"`
						}{Name: "ws-workspace-a"}},
						{Metadata: struct {
							Name string `json:"name"`
						}{Name: "skyforge"}},
						{Metadata: struct {
							Name string `json:"name"`
						}{Name: "default"}},
					},
				}
				resp.Metadata.Continue = "c1"
				_ = json.NewEncoder(w).Encode(resp)
				return
			}
			resp := listResponse[struct {
				Metadata struct {
					Name string `json:"name"`
				} `json:"metadata"`
			}]{
				Items: []struct {
					Metadata struct {
						Name string `json:"name"`
					} `json:"metadata"`
				}{
					{Metadata: struct {
						Name string `json:"name"`
					}{Name: "ws-workspace-b"}},
				},
			}
			resp.Metadata.Continue = ""
			_ = json.NewEncoder(w).Encode(resp)
			return

		case "/api/v1/pods":
			cont := r.URL.Query().Get("continue")
			if cont == "" {
				resp := listResponse[struct {
					Metadata struct {
						Namespace string `json:"namespace"`
					} `json:"metadata"`
					Status struct {
						Phase string `json:"phase"`
					} `json:"status"`
				}]{
					Items: []struct {
						Metadata struct {
							Namespace string `json:"namespace"`
						} `json:"metadata"`
						Status struct {
							Phase string `json:"phase"`
						} `json:"status"`
					}{
						{Metadata: struct {
							Namespace string `json:"namespace"`
						}{Namespace: "ws-workspace-a"}, Status: struct {
							Phase string `json:"phase"`
						}{Phase: "Running"}},
						{Metadata: struct {
							Namespace string `json:"namespace"`
						}{Namespace: "ws-workspace-a"}, Status: struct {
							Phase string `json:"phase"`
						}{Phase: "Pending"}},
						{Metadata: struct {
							Namespace string `json:"namespace"`
						}{Namespace: "skyforge"}, Status: struct {
							Phase string `json:"phase"`
						}{Phase: "Pending"}},
						{Metadata: struct {
							Namespace string `json:"namespace"`
						}{Namespace: "kube-system"}, Status: struct {
							Phase string `json:"phase"`
						}{Phase: "Running"}},
					},
				}
				resp.Metadata.Continue = "p2"
				_ = json.NewEncoder(w).Encode(resp)
				return
			}
			resp := listResponse[struct {
				Metadata struct {
					Namespace string `json:"namespace"`
				} `json:"metadata"`
				Status struct {
					Phase string `json:"phase"`
				} `json:"status"`
			}]{
				Items: []struct {
					Metadata struct {
						Namespace string `json:"namespace"`
					} `json:"metadata"`
					Status struct {
						Phase string `json:"phase"`
					} `json:"status"`
				}{
					{Metadata: struct {
						Namespace string `json:"namespace"`
					}{Namespace: "ws-workspace-b"}, Status: struct {
						Phase string `json:"phase"`
					}{Phase: "Pending"}},
				},
			}
			resp.Metadata.Continue = ""
			_ = json.NewEncoder(w).Encode(resp)
			return

		default:
			http.NotFound(w, r)
			return
		}
	}))
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)

	counts, err := CollectInventoryCountsWithRequest(
		ctx,
		srv.Client(),
		"skyforge",
		srv.URL,
		func(ctx context.Context, method, u string) (*http.Request, error) {
			return http.NewRequestWithContext(ctx, method, u, nil)
		},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if counts.NamespacesTotal != 4 {
		t.Fatalf("NamespacesTotal expected 4, got %d", counts.NamespacesTotal)
	}
	if counts.NamespacesWS != 2 {
		t.Fatalf("NamespacesWS expected 2, got %d", counts.NamespacesWS)
	}
	if counts.PodsTotal != 5 {
		t.Fatalf("PodsTotal expected 5, got %d", counts.PodsTotal)
	}
	if counts.PodsPending != 3 {
		t.Fatalf("PodsPending expected 3, got %d", counts.PodsPending)
	}
	if counts.PodsWSTotal != 3 {
		t.Fatalf("PodsWSTotal expected 3, got %d", counts.PodsWSTotal)
	}
	if counts.PodsWSPending != 2 {
		t.Fatalf("PodsWSPending expected 2, got %d", counts.PodsWSPending)
	}
	if counts.PodsPlatformTotal != 1 {
		t.Fatalf("PodsPlatformTotal expected 1, got %d", counts.PodsPlatformTotal)
	}
	if counts.PodsPlatformPending != 1 {
		t.Fatalf("PodsPlatformPending expected 1, got %d", counts.PodsPlatformPending)
	}
}
