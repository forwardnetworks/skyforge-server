package skyforge

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"encore.dev/beta/errs"
)

type ToolServiceStatus struct {
	ID                string `json:"id"`
	Label             string `json:"label"`
	Mode              string `json:"mode"` // "shared" or "personal"
	DesiredReplicas   int32  `json:"desiredReplicas"`
	AvailableReplicas int32  `json:"availableReplicas"`
}

type ToolServicesStatusResponse struct {
	Services []ToolServiceStatus `json:"services"`
}

type ToolServiceActionResponse struct {
	Status ToolServiceStatus `json:"status"`
}

type kubeDeployment struct {
	Spec struct {
		Replicas *int32 `json:"replicas"`
	} `json:"spec"`
	Status struct {
		AvailableReplicas int32 `json:"availableReplicas"`
		Replicas          int32 `json:"replicas"`
	} `json:"status"`
}

func kubeGetDeployment(ctx context.Context, name string) (*kubeDeployment, error) {
	client, err := kubeHTTPClient()
	if err != nil {
		return nil, err
	}
	token, err := kubeToken()
	if err != nil {
		return nil, err
	}
	ns := kubeNamespace()
	url := fmt.Sprintf("https://kubernetes.default.svc/apis/apps/v1/namespaces/%s/deployments/%s", ns, name)
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
		return nil, fmt.Errorf("kube get deployment failed: %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	var d kubeDeployment
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		return nil, err
	}
	return &d, nil
}

func kubePatchDeploymentReplicas(ctx context.Context, name string, replicas int32) (*kubeDeployment, error) {
	client, err := kubeHTTPClient()
	if err != nil {
		return nil, err
	}
	token, err := kubeToken()
	if err != nil {
		return nil, err
	}
	ns := kubeNamespace()
	url := fmt.Sprintf("https://kubernetes.default.svc/apis/apps/v1/namespaces/%s/deployments/%s", ns, name)
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
		return nil, fmt.Errorf("kube patch deployment failed: %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	var d kubeDeployment
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		return nil, err
	}
	return &d, nil
}

func toolDefinitions() []ToolServiceStatus {
	return []ToolServiceStatus{}
}

func deploymentNameForTool(id string) (string, bool) {
	switch id {
	default:
		return "", false
	}
}

func readInt32Ptr(v *int32, fallback int32) int32 {
	if v == nil {
		return fallback
	}
	return *v
}

// GetToolServicesStatus returns start/stop state for personal toolchain services.
//
//encore:api auth method=GET path=/api/tooling/services
func (s *Service) GetToolServicesStatus(ctx context.Context) (*ToolServicesStatusResponse, error) {
	if _, err := requireAuthUser(); err != nil {
		return nil, err
	}
	out := []ToolServiceStatus{}
	for _, tool := range toolDefinitions() {
		depName, ok := deploymentNameForTool(tool.ID)
		if !ok {
			continue
		}
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		d, err := kubeGetDeployment(ctx, depName)
		cancel()
		if err != nil {
			// Non-fatal; expose as stopped/unknown.
			out = append(out, tool)
			continue
		}
		desired := readInt32Ptr(d.Spec.Replicas, 1)
		out = append(out, ToolServiceStatus{
			ID:                tool.ID,
			Label:             tool.Label,
			Mode:              tool.Mode,
			DesiredReplicas:   desired,
			AvailableReplicas: d.Status.AvailableReplicas,
		})
	}
	return &ToolServicesStatusResponse{Services: out}, nil
}

type ToolServiceActionRequest struct {
	Replicas string `json:"replicas,omitempty"`
}

// SetToolServiceReplicas sets the replica count for a personal toolchain service.
//
//encore:api auth method=POST path=/api/tooling/services/:id/replicas
func (s *Service) SetToolServiceReplicas(ctx context.Context, id string, req *ToolServiceActionRequest) (*ToolServiceActionResponse, error) {
	if _, err := requireAuthUser(); err != nil {
		return nil, err
	}
	id = strings.TrimSpace(id)
	depName, ok := deploymentNameForTool(id)
	if !ok {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("unknown tool service").Err()
	}
	label := id
	for _, tool := range toolDefinitions() {
		if tool.ID == id {
			label = tool.Label
			break
		}
	}
	replicas := int32(0)
	if req != nil && strings.TrimSpace(req.Replicas) != "" {
		v, err := strconv.Atoi(strings.TrimSpace(req.Replicas))
		if err != nil || v < 0 || v > 3 {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("replicas must be between 0 and 3").Err()
		}
		replicas = int32(v)
	} else {
		// Default: toggle on.
		replicas = 1
	}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	d, err := kubePatchDeploymentReplicas(ctx, depName, replicas)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to scale tool service").Err()
	}
	desired := readInt32Ptr(d.Spec.Replicas, replicas)
	return &ToolServiceActionResponse{
		Status: ToolServiceStatus{
			ID:                id,
			Label:             label,
			Mode:              "personal",
			DesiredReplicas:   desired,
			AvailableReplicas: d.Status.AvailableReplicas,
		},
	}, nil
}
