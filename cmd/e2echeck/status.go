package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type e2eStatusFile struct {
	UpdatedAt string                   `json:"updatedAt"`
	Devices   map[string]e2eDeviceStat `json:"devices"`
}

type e2eDeviceStat struct {
	Device     string `json:"device"`
	Status     string `json:"status"` // pass|fail|skip|unknown
	UpdatedAt  string `json:"updatedAt"`
	Template   string `json:"template,omitempty"`
	DeployType string `json:"deployType,omitempty"`
	TaskID     int    `json:"taskId,omitempty"`
	Error      string `json:"error,omitempty"`
	Notes      string `json:"notes,omitempty"`
}

type e2eStatusRecorder struct {
	jsonPath string
	mdPath   string
	state    e2eStatusFile
}

func newE2EStatusRecorder(jsonPath, mdPath string) (*e2eStatusRecorder, error) {
	jsonPath = strings.TrimSpace(jsonPath)
	mdPath = strings.TrimSpace(mdPath)
	if jsonPath == "" || mdPath == "" {
		return nil, nil
	}
	r := &e2eStatusRecorder{
		jsonPath: jsonPath,
		mdPath:   mdPath,
		state: e2eStatusFile{
			Devices: map[string]e2eDeviceStat{},
		},
	}
	if raw, err := os.ReadFile(jsonPath); err == nil && len(raw) > 0 {
		_ = json.Unmarshal(raw, &r.state)
		if r.state.Devices == nil {
			r.state.Devices = map[string]e2eDeviceStat{}
		}
	}
	return r, nil
}

func (r *e2eStatusRecorder) update(device string, status string, template string, deployType string, taskID int, errMsg string, notes string) {
	if r == nil {
		return
	}
	device = strings.TrimSpace(device)
	if device == "" {
		return
	}
	now := time.Now().UTC().Format(time.RFC3339)
	r.state.UpdatedAt = now
	r.state.Devices[device] = e2eDeviceStat{
		Device:     device,
		Status:     strings.TrimSpace(status),
		UpdatedAt:  now,
		Template:   strings.TrimSpace(template),
		DeployType: strings.TrimSpace(deployType),
		TaskID:     taskID,
		Error:      strings.TrimSpace(errMsg),
		Notes:      strings.TrimSpace(notes),
	}
}

func (r *e2eStatusRecorder) flush() error {
	if r == nil {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(r.jsonPath), 0o755); err != nil {
		return err
	}
	out, err := json.MarshalIndent(r.state, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(r.jsonPath, out, 0o644); err != nil {
		return err
	}

	return os.WriteFile(r.mdPath, []byte(renderE2EStatusMarkdown(r.state)), 0o644)
}

func renderE2EStatusMarkdown(s e2eStatusFile) string {
	lines := []string{}
	lines = append(lines, "# Skyforge E2E Device Reachability Status", "")
	if strings.TrimSpace(s.UpdatedAt) != "" {
		lines = append(lines, fmt.Sprintf("Last updated: %s", s.UpdatedAt), "")
	}
	lines = append(lines, "Scope: baseline **deploy + SSH reachability** for each onboarded Netlab device type (netlab-c9s → clabernetes + vrnetlab hybrid).", "")
	lines = append(lines, "Legend: ✅ pass · ❌ fail · ⏭ skipped · ❔ unknown", "")
	lines = append(lines, "| Device type | Status | Updated | Notes |", "| --- | --- | --- | --- |")

	devs := make([]string, 0, len(s.Devices))
	for d := range s.Devices {
		devs = append(devs, d)
	}
	sort.Strings(devs)
	for _, d := range devs {
		st := s.Devices[d]
		icon := "❔"
		switch strings.ToLower(strings.TrimSpace(st.Status)) {
		case "pass", "ok", "success":
			icon = "✅"
		case "fail", "failed", "error":
			icon = "❌"
		case "skip", "skipped":
			icon = "⏭"
		}
		notes := strings.TrimSpace(st.Notes)
		if notes == "" {
			notes = strings.TrimSpace(st.Error)
		}
		notes = strings.ReplaceAll(notes, "\n", " ")
		lines = append(lines, fmt.Sprintf("| `%s` | %s | %s | %s |", d, icon, strings.TrimSpace(st.UpdatedAt), notes))
	}
	lines = append(lines, "")
	lines = append(lines, "## How to run", "")
	lines = append(lines, "Run from `skyforge-private/server`:", "", "```bash", "SKYFORGE_E2E_DEPLOY=true \\")
	lines = append(lines, "SKYFORGE_E2E_SSH_PROBE_MODE=api \\")
	lines = append(lines, "SKYFORGE_E2E_DEVICE_SET=all \\")
	lines = append(lines, "go run ./cmd/e2echeck --run-generated", "```", "")
	lines = append(lines, "Notes:", "- `SKYFORGE_E2E_SSH_PROBE_MODE=api` uses Skyforge’s `/api/admin/e2e/sshprobe` endpoint (fast, no dependency on a running Forward collector).")
	lines = append(lines, "- If a device fails, inspect its `ws-e2e-*` namespace and the `clabernetes-launcher-*` logs first.", "")

	return strings.Join(lines, "\n")
}

