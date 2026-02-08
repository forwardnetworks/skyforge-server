package skyforge

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"encore.dev/beta/errs"
)

const elasticToolsLastActivitySettingKey = "elastic_tools_last_activity_rfc3339"

type ElasticToolServiceStatus struct {
	ID                string `json:"id"`   // elasticsearch | kibana
	Kind              string `json:"kind"` // statefulset | deployment
	DesiredReplicas   int32  `json:"desiredReplicas"`
	AvailableReplicas int32  `json:"availableReplicas"`
}

type ElasticToolsStatusResponse struct {
	Enabled          bool                       `json:"enabled"`
	AutosleepEnabled bool                       `json:"autosleepEnabled"`
	IdleMinutes      int                        `json:"idleMinutes"`
	Now              string                     `json:"now"`
	LastActivityAt   string                     `json:"lastActivityAt,omitempty"`
	Services         []ElasticToolServiceStatus `json:"services"`
}

type ElasticToolsActionResponse struct {
	Status ElasticToolsStatusResponse `json:"status"`
}

type kubeStatefulSet struct {
	Spec struct {
		Replicas *int32 `json:"replicas"`
	} `json:"spec"`
	Status struct {
		AvailableReplicas int32 `json:"availableReplicas"`
		ReadyReplicas     int32 `json:"readyReplicas"`
		Replicas          int32 `json:"replicas"`
	} `json:"status"`
}

func kubeGetStatefulSet(ctx context.Context, name string) (*kubeStatefulSet, error) {
	client, err := kubeHTTPClient()
	if err != nil {
		return nil, err
	}
	token, err := kubeToken()
	if err != nil {
		return nil, err
	}
	ns := kubeNamespace()
	url := fmt.Sprintf("https://kubernetes.default.svc/apis/apps/v1/namespaces/%s/statefulsets/%s", ns, name)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
		return nil, fmt.Errorf("kube get statefulset failed: %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	var ss kubeStatefulSet
	if err := json.NewDecoder(resp.Body).Decode(&ss); err != nil {
		return nil, err
	}
	return &ss, nil
}

func kubePatchStatefulSetReplicas(ctx context.Context, name string, replicas int32) (*kubeStatefulSet, error) {
	client, err := kubeHTTPClient()
	if err != nil {
		return nil, err
	}
	token, err := kubeToken()
	if err != nil {
		return nil, err
	}
	ns := kubeNamespace()
	url := fmt.Sprintf("https://kubernetes.default.svc/apis/apps/v1/namespaces/%s/statefulsets/%s", ns, name)
	patchBody, _ := json.Marshal(map[string]any{"spec": map[string]any{"replicas": replicas}})
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, url, bytes.NewReader(patchBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/strategic-merge-patch+json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
		return nil, fmt.Errorf("kube patch statefulset failed: %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	var ss kubeStatefulSet
	if err := json.NewDecoder(resp.Body).Decode(&ss); err != nil {
		return nil, err
	}
	return &ss, nil
}

func (s *Service) elasticToolsConfig() (enabled bool, autosleepEnabled bool, idleMinutes int) {
	enabled = s != nil && s.cfg.Features.ElasticEnabled
	autosleepEnabled = s != nil && s.cfg.Elastic.ToolsAutosleepEnabled
	idleMinutes = 30
	if s != nil && s.cfg.Elastic.ToolsAutosleepIdleMinutes > 0 {
		idleMinutes = s.cfg.Elastic.ToolsAutosleepIdleMinutes
	}
	return enabled, autosleepEnabled, idleMinutes
}

func parseRFC3339Time(raw string) (time.Time, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, false
	}
	if t, err := time.Parse(time.RFC3339Nano, raw); err == nil {
		return t.UTC(), true
	}
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return t.UTC(), true
	}
	return time.Time{}, false
}

func shouldElasticToolsSleep(lastActivity time.Time, idle time.Duration, now time.Time) bool {
	if lastActivity.IsZero() {
		return false
	}
	if idle <= 0 {
		idle = 30 * time.Minute
	}
	return now.Sub(lastActivity) > idle
}

func (s *Service) touchElasticToolsActivity(ctx context.Context) {
	if s == nil || s.db == nil {
		return
	}
	enabled, autosleepEnabled, _ := s.elasticToolsConfig()
	if !enabled || !autosleepEnabled {
		return
	}
	_ = upsertSetting(ctx, s.db, elasticToolsLastActivitySettingKey, time.Now().UTC().Format(time.RFC3339Nano))
}

func (s *Service) elasticToolsStatus(ctx context.Context) (ElasticToolsStatusResponse, error) {
	enabled, autosleepEnabled, idleMinutes := s.elasticToolsConfig()
	now := time.Now().UTC()

	lastActivityAt := ""
	if s != nil && s.db != nil {
		if v, ok, err := getSetting(ctx, s.db, elasticToolsLastActivitySettingKey); err == nil && ok {
			lastActivityAt = strings.TrimSpace(v)
		}
	}

	// Kibana (Deployment)
	ctxK, cancelK := context.WithTimeout(ctx, 5*time.Second)
	d, err := kubeGetDeployment(ctxK, "kibana")
	cancelK()
	if err != nil {
		return ElasticToolsStatusResponse{}, err
	}
	desiredK := readInt32Ptr(d.Spec.Replicas, 1)

	// Elasticsearch (StatefulSet)
	ctxE, cancelE := context.WithTimeout(ctx, 5*time.Second)
	ss, err := kubeGetStatefulSet(ctxE, "elasticsearch")
	cancelE()
	if err != nil {
		return ElasticToolsStatusResponse{}, err
	}
	desiredE := readInt32Ptr(ss.Spec.Replicas, 1)
	availableE := ss.Status.AvailableReplicas
	if ss.Status.ReadyReplicas > availableE {
		availableE = ss.Status.ReadyReplicas
	}

	services := []ElasticToolServiceStatus{
		{
			ID:                "kibana",
			Kind:              "deployment",
			DesiredReplicas:   desiredK,
			AvailableReplicas: d.Status.AvailableReplicas,
		},
		{
			ID:                "elasticsearch",
			Kind:              "statefulset",
			DesiredReplicas:   desiredE,
			AvailableReplicas: availableE,
		},
	}

	return ElasticToolsStatusResponse{
		Enabled:          enabled,
		AutosleepEnabled: autosleepEnabled,
		IdleMinutes:      idleMinutes,
		Now:              now.Format(time.RFC3339Nano),
		LastActivityAt:   lastActivityAt,
		Services:         services,
	}, nil
}

// GetElasticToolsStatus returns the current sleep/wake status for in-cluster Elasticsearch + Kibana.
//
//encore:api auth method=GET path=/api/system/elastic/tools/status
func (s *Service) GetElasticToolsStatus(ctx context.Context) (*ElasticToolsStatusResponse, error) {
	if _, err := requireAuthUser(); err != nil {
		return nil, err
	}
	st, err := s.elasticToolsStatus(ctx)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to read elastic tools status").Err()
	}
	return &st, nil
}

// WakeElasticTools scales in-cluster Elasticsearch + Kibana to 1 replica (best-effort).
//
//encore:api auth method=POST path=/api/system/elastic/tools/wake
func (s *Service) WakeElasticTools(ctx context.Context) (*ElasticToolsActionResponse, error) {
	if _, err := requireAuthUser(); err != nil {
		return nil, err
	}
	enabled, _, _ := s.elasticToolsConfig()
	if !enabled {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg("elastic is disabled").Err()
	}

	ctxScale, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	// Order: ES first, then Kibana.
	_, _ = kubePatchStatefulSetReplicas(ctxScale, "elasticsearch", 1)
	_, _ = kubePatchDeploymentReplicas(ctxScale, "kibana", 1)

	s.touchElasticToolsActivity(ctx)
	st, err := s.elasticToolsStatus(ctx)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to read elastic tools status").Err()
	}
	return &ElasticToolsActionResponse{Status: st}, nil
}

// SleepElasticTools scales in-cluster Elasticsearch + Kibana to 0 replicas (admin only).
//
//encore:api auth method=POST path=/api/system/elastic/tools/sleep tag:admin
func (s *Service) SleepElasticTools(ctx context.Context) (*ElasticToolsActionResponse, error) {
	if _, err := requireAuthUser(); err != nil {
		return nil, err
	}
	enabled, _, _ := s.elasticToolsConfig()
	if !enabled {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg("elastic is disabled").Err()
	}

	ctxScale, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	_, _ = kubePatchDeploymentReplicas(ctxScale, "kibana", 0)
	_, _ = kubePatchStatefulSetReplicas(ctxScale, "elasticsearch", 0)

	s.touchElasticToolsActivity(ctx)
	st, err := s.elasticToolsStatus(ctx)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to read elastic tools status").Err()
	}
	return &ElasticToolsActionResponse{Status: st}, nil
}

type ElasticAutosleepTickParams struct {
	Token string `header:"X-Skyforge-Internal-Token" json:"-"`
}

// ElasticAutosleepTick checks for inactivity and scales Elastic tools down to 0 when idle.
//
// This is intended to be called from a CronJob in-cluster using SKYFORGE_INTERNAL_TOKEN.
//
//encore:api public method=POST path=/internal/elastic/tools/autosleep-tick
func (s *Service) ElasticAutosleepTick(ctx context.Context, params *ElasticAutosleepTickParams) error {
	if params == nil {
		return errs.B().Code(errs.InvalidArgument).Msg("invalid payload").Err()
	}
	if err := s.requireInternalIngest(params.Token); err != nil {
		return err
	}

	enabled, autosleepEnabled, idleMinutes := s.elasticToolsConfig()
	if !enabled || !autosleepEnabled {
		return nil
	}
	if s.db == nil {
		return nil
	}

	now := time.Now().UTC()
	raw, ok, err := getSetting(ctx, s.db, elasticToolsLastActivitySettingKey)
	if err != nil {
		return nil
	}
	if !ok || strings.TrimSpace(raw) == "" {
		// First tick after enabling: set baseline and don't sleep immediately.
		_ = upsertSetting(ctx, s.db, elasticToolsLastActivitySettingKey, now.Format(time.RFC3339Nano))
		return nil
	}
	lastActivity, ok := parseRFC3339Time(raw)
	if !ok {
		_ = upsertSetting(ctx, s.db, elasticToolsLastActivitySettingKey, now.Format(time.RFC3339Nano))
		return nil
	}

	if !shouldElasticToolsSleep(lastActivity, time.Duration(idleMinutes)*time.Minute, now) {
		return nil
	}

	ctxScale, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	_, _ = kubePatchDeploymentReplicas(ctxScale, "kibana", 0)
	_, _ = kubePatchStatefulSetReplicas(ctxScale, "elasticsearch", 0)
	return nil
}
