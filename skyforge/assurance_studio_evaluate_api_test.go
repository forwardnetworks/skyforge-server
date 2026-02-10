package skyforge

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func boolPtr(v bool) *bool { return &v }

func TestAssuranceStudioEvaluate_SinglePathsBulkCall_AllPhases(t *testing.T) {
	t.Parallel()

	var pathsBulkCalls int32

	// Fake Forward API.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/paths-bulk") {
			http.NotFound(w, r)
			return
		}
		atomic.AddInt32(&pathsBulkCalls, 1)

		// Validate we got a single shared request with routing defaults applied.
		body, _ := io.ReadAll(r.Body)
		defer r.Body.Close()
		var got fwdPathSearchBulkRequestFull
		if err := json.Unmarshal(body, &got); err != nil {
			t.Fatalf("failed to decode request payload: %v", err)
		}
		if len(got.Queries) != 1 {
			t.Fatalf("expected 1 query, got %d", len(got.Queries))
		}
		// With routing enabled and no explicit routing.Forward.MaxResults, the shared request should
		// ask Forward for multiple candidates (union across phases).
		if got.MaxResults < 3 {
			t.Fatalf("expected MaxResults >= 3 (got %d)", got.MaxResults)
		}

		// Minimal Forward response: one demand, one path, one enforcement hop.
		out := []fwdPathSearchResponseFull{{
			Info: prFwdPathInfo{
				TotalHits: 1,
				Paths: []prFwdPath{{
					ForwardingOutcome: "DELIVERED",
					SecurityOutcome:   "ALLOWED",
					Hops: []prFwdPathHop{{
						DeviceName:       "fw1",
						DeviceType:       "FIREWALL",
						IngressInterface: "Gi0/0",
						EgressInterface:  "Gi0/1",
					}},
				}},
			},
			TimedOut: false,
			QueryURL: "http://forward.local/query",
		}}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	}))
	defer srv.Close()

	client, err := newForwardClient(forwardCredentials{
		BaseURL:  srv.URL,
		Username: "u",
		Password: "p",
	})
	if err != nil {
		t.Fatalf("failed to create forward client: %v", err)
	}

	req := &AssuranceStudioEvaluateRequest{
		SnapshotID: "snap-1",
		Window:     "7d",
		Demands: []AssuranceTrafficDemand{{
			SrcIP: "10.0.0.1",
			DstIP: "10.0.0.2",
		}},
		Phases: &AssuranceStudioEvaluatePhases{
			Routing:  boolPtr(true),
			Capacity: boolPtr(true),
			Security: boolPtr(true),
		},
		Capacity: &AssuranceStudioCapacityOptions{
			PerfFallback: boolPtr(false), // ensure no extra Forward history calls in this test
		},
	}

	pre := assuranceStudioPreload{
		asOf:    time.Unix(0, 0).UTC(),
		rollups: nil,
		ifaces:  nil,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = assuranceStudioEvaluateWithClient(ctx, client, "ws1", "netref1", "fwd-net-1", req, pre)
	if err != nil {
		t.Fatalf("assuranceStudioEvaluateWithClient returned error: %v", err)
	}

	if got := atomic.LoadInt32(&pathsBulkCalls); got != 1 {
		t.Fatalf("expected exactly 1 paths-bulk call, got %d", got)
	}
}

func TestAssuranceStudioEvaluate_RoutingBaseline_UsesSecondPathsBulkCall(t *testing.T) {
	t.Parallel()

	var pathsBulkCalls int32
	var sawBaseline int32
	var sawCompare int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/paths-bulk") {
			http.NotFound(w, r)
			return
		}
		atomic.AddInt32(&pathsBulkCalls, 1)

		snap := strings.TrimSpace(r.URL.Query().Get("snapshotId"))
		if snap == "base-1" {
			atomic.StoreInt32(&sawBaseline, 1)
		}
		if snap == "snap-1" {
			atomic.StoreInt32(&sawCompare, 1)
		}

		body, _ := io.ReadAll(r.Body)
		defer r.Body.Close()
		var got fwdPathSearchBulkRequestFull
		if err := json.Unmarshal(body, &got); err != nil {
			t.Fatalf("failed to decode request payload: %v", err)
		}
		if snap == "base-1" && got.MaxReturnPathResults != 0 {
			t.Fatalf("expected baseline MaxReturnPathResults=0, got %d", got.MaxReturnPathResults)
		}

		out := []fwdPathSearchResponseFull{{
			Info: prFwdPathInfo{
				TotalHits: 1,
				Paths: []prFwdPath{{
					ForwardingOutcome: "DELIVERED",
					SecurityOutcome:   "ALLOWED",
					Hops: []prFwdPathHop{{
						DeviceName:       "fw1",
						DeviceType:       "FIREWALL",
						IngressInterface: "Gi0/0",
						EgressInterface:  "Gi0/1",
					}},
				}},
			},
			TimedOut: false,
			QueryURL: "http://forward.local/query",
		}}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	}))
	defer srv.Close()

	client, err := newForwardClient(forwardCredentials{
		BaseURL:  srv.URL,
		Username: "u",
		Password: "p",
	})
	if err != nil {
		t.Fatalf("failed to create forward client: %v", err)
	}

	req := &AssuranceStudioEvaluateRequest{
		SnapshotID:         "snap-1",
		BaselineSnapshotID: "base-1",
		Window:             "7d",
		Demands: []AssuranceTrafficDemand{{
			SrcIP: "10.0.0.1",
			DstIP: "10.0.0.2",
		}},
		Phases: &AssuranceStudioEvaluatePhases{
			Routing:  boolPtr(true),
			Capacity: boolPtr(false),
			Security: boolPtr(false),
		},
		Routing: &AssuranceStudioRoutingOptions{
			IncludeHops: true, // so diff can evaluate hop changes if needed
		},
	}

	pre := assuranceStudioPreload{asOf: time.Unix(0, 0).UTC()}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := assuranceStudioEvaluateWithClient(ctx, client, "ws1", "netref1", "fwd-net-1", req, pre)
	if err != nil {
		t.Fatalf("assuranceStudioEvaluateWithClient returned error: %v", err)
	}

	if got := atomic.LoadInt32(&pathsBulkCalls); got != 2 {
		t.Fatalf("expected exactly 2 paths-bulk calls, got %d", got)
	}
	if atomic.LoadInt32(&sawBaseline) != 1 || atomic.LoadInt32(&sawCompare) != 1 {
		t.Fatalf("expected both baseline and compare snapshots to be requested (baseline=%v compare=%v)", atomic.LoadInt32(&sawBaseline) == 1, atomic.LoadInt32(&sawCompare) == 1)
	}
	if resp.RoutingBaseline == nil || resp.RoutingDiff == nil {
		t.Fatalf("expected routingBaseline and routingDiff to be populated")
	}
}
