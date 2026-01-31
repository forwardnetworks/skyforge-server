package governanceutil

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// IntervalString converts a duration into a Postgres interval string.
// We intentionally stick to whole seconds.
func IntervalString(d time.Duration) string {
	secs := int64(d.Seconds())
	if secs <= 0 {
		return "0 seconds"
	}
	return fmt.Sprintf("%d seconds", secs)
}

// Percentile returns the p-th percentile using the nearest-rank method.
func Percentile(values []float64, p float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sort.Float64s(values)
	if p <= 0 {
		return values[0]
	}
	if p >= 1 {
		return values[len(values)-1]
	}
	rank := int(math.Ceil(p*float64(len(values)))) - 1
	if rank < 0 {
		rank = 0
	}
	if rank >= len(values) {
		rank = len(values) - 1
	}
	return values[rank]
}

type InventoryCounts struct {
	NamespacesTotal int
	NamespacesWS    int

	PodsTotal           int
	PodsPending         int
	PodsWSTotal         int
	PodsWSPending       int
	PodsPlatformTotal   int
	PodsPlatformPending int
}

type RequestFunc func(ctx context.Context, method, url string) (*http.Request, error)

// KubeDefaultAPIBaseURL is the in-cluster Kubernetes API DNS name.
const KubeDefaultAPIBaseURL = "https://kubernetes.default.svc"

type listMetadata struct {
	Continue string `json:"continue"`
}

type namespaceList struct {
	Items []struct {
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
	} `json:"items"`
	Metadata listMetadata `json:"metadata"`
}

type podList struct {
	Items []struct {
		Metadata struct {
			Namespace string `json:"namespace"`
		} `json:"metadata"`
		Status struct {
			Phase string `json:"phase"`
		} `json:"status"`
	} `json:"items"`
	Metadata listMetadata `json:"metadata"`
}

func CollectInventoryCountsWithRequest(ctx context.Context, client *http.Client, platformNamespace string, apiBaseURL string, reqFn RequestFunc) (InventoryCounts, error) {
	var counts InventoryCounts

	apiBaseURL = strings.TrimRight(strings.TrimSpace(apiBaseURL), "/")
	if apiBaseURL == "" {
		return counts, fmt.Errorf("empty kube api base url")
	}

	// Namespaces (paginated).
	{
		cont := ""
		for {
			u, err := url.Parse(apiBaseURL + "/api/v1/namespaces")
			if err != nil {
				return counts, err
			}
			q := u.Query()
			q.Set("limit", strconv.Itoa(500))
			if cont != "" {
				q.Set("continue", cont)
			}
			u.RawQuery = q.Encode()

			req, err := reqFn(ctx, http.MethodGet, u.String())
			if err != nil {
				return counts, err
			}
			resp, err := client.Do(req)
			if err != nil {
				return counts, err
			}
			func() {
				defer resp.Body.Close()
				if resp.StatusCode < 200 || resp.StatusCode >= 300 {
					err = fmt.Errorf("kube namespaces list: status=%s", resp.Status)
					return
				}
				var parsed namespaceList
				if err2 := json.NewDecoder(resp.Body).Decode(&parsed); err2 != nil {
					err = err2
					return
				}
				for _, item := range parsed.Items {
					name := strings.TrimSpace(item.Metadata.Name)
					if name == "" {
						continue
					}
					counts.NamespacesTotal++
					if strings.HasPrefix(name, "ws-") {
						counts.NamespacesWS++
					}
				}
				cont = strings.TrimSpace(parsed.Metadata.Continue)
			}()
			if err != nil {
				return counts, err
			}
			if cont == "" {
				break
			}
		}
	}

	// Pods (all namespaces), paginated.
	{
		cont := ""
		for {
			u, err := url.Parse(apiBaseURL + "/api/v1/pods")
			if err != nil {
				return counts, err
			}
			q := u.Query()
			q.Set("limit", strconv.Itoa(500))
			if cont != "" {
				q.Set("continue", cont)
			}
			u.RawQuery = q.Encode()

			req, err := reqFn(ctx, http.MethodGet, u.String())
			if err != nil {
				return counts, err
			}
			resp, err := client.Do(req)
			if err != nil {
				return counts, err
			}
			func() {
				defer resp.Body.Close()
				if resp.StatusCode < 200 || resp.StatusCode >= 300 {
					err = fmt.Errorf("kube pods list: status=%s", resp.Status)
					return
				}
				var parsed podList
				if err2 := json.NewDecoder(resp.Body).Decode(&parsed); err2 != nil {
					err = err2
					return
				}
				for _, item := range parsed.Items {
					ns := strings.TrimSpace(item.Metadata.Namespace)
					phase := strings.TrimSpace(item.Status.Phase)
					counts.PodsTotal++
					if phase == "Pending" {
						counts.PodsPending++
					}
					if strings.HasPrefix(ns, "ws-") {
						counts.PodsWSTotal++
						if phase == "Pending" {
							counts.PodsWSPending++
						}
					}
					if ns == platformNamespace {
						counts.PodsPlatformTotal++
						if phase == "Pending" {
							counts.PodsPlatformPending++
						}
					}
				}
				cont = strings.TrimSpace(parsed.Metadata.Continue)
			}()
			if err != nil {
				return counts, err
			}
			if cont == "" {
				break
			}
		}
	}

	return counts, nil
}
