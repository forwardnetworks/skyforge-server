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

func midnightUTC(t time.Time) time.Time {
	t = t.UTC()
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
}

type e2eStatusFile struct {
	GeneratedAt string                   `json:"generated_at"`
	Devices     map[string]e2eDeviceStat `json:"devices"`
	Rows        []e2eDeviceStat          `json:"rows,omitempty"`
}

type e2eDeviceStat struct {
	Device     string `json:"device"`
	Status     string `json:"status"` // pass|fail|skip|unknown
	UpdatedAt  string `json:"updatedAt"`
	LastOKAt   string `json:"last_ok_at,omitempty"`
	LastFailAt string `json:"last_fail_at,omitempty"`
	LastError  string `json:"last_error,omitempty"`
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
		// Old format might have rows but no devices; reconstruct.
		if len(r.state.Devices) == 0 && len(r.state.Rows) > 0 {
			for _, row := range r.state.Rows {
				if strings.TrimSpace(row.Device) == "" {
					continue
				}
				r.state.Devices[row.Device] = row
			}
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
	r.state.GeneratedAt = now
	prev := r.state.Devices[device]
	st := e2eDeviceStat{
		Device:     device,
		Status:     strings.TrimSpace(status),
		UpdatedAt:  now,
		LastOKAt:   prev.LastOKAt,
		LastFailAt: prev.LastFailAt,
		LastError:  prev.LastError,
		Template:   strings.TrimSpace(template),
		DeployType: strings.TrimSpace(deployType),
		TaskID:     taskID,
		Error:      strings.TrimSpace(errMsg),
		Notes:      strings.TrimSpace(notes),
	}
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "pass", "ok", "success":
		st.LastOKAt = now
		st.LastError = ""
	case "fail", "failed", "error":
		st.LastFailAt = now
		st.LastError = strings.TrimSpace(errMsg)
	}
	r.state.Devices[device] = st
}

func (r *e2eStatusRecorder) syncDeviceSet(devices []string) {
	if r == nil {
		return
	}
	set := map[string]struct{}{}
	for _, d := range devices {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		set[d] = struct{}{}
	}
	if len(set) == 0 {
		return
	}
	if r.state.Devices == nil {
		r.state.Devices = map[string]e2eDeviceStat{}
	}

	for d := range r.state.Devices {
		if _, ok := set[d]; !ok {
			delete(r.state.Devices, d)
		}
	}

	notYetRunAt := midnightUTC(time.Now()).Format(time.RFC3339)
	for d := range set {
		if _, ok := r.state.Devices[d]; ok {
			continue
		}
		r.state.Devices[d] = e2eDeviceStat{
			Device:    d,
			Status:    "unknown",
			UpdatedAt: notYetRunAt,
			Notes:     "not yet run",
		}
	}
}

func (r *e2eStatusRecorder) flush() error {
	if r == nil {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(r.jsonPath), 0o755); err != nil {
		return err
	}
	// Provide a stable, easy-to-consume list view as well.
	devs := make([]string, 0, len(r.state.Devices))
	for d := range r.state.Devices {
		devs = append(devs, d)
	}
	sort.Strings(devs)
	rows := make([]e2eDeviceStat, 0, len(devs))
	for _, d := range devs {
		rows = append(rows, r.state.Devices[d])
	}
	r.state.Rows = rows

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
	if strings.TrimSpace(s.GeneratedAt) != "" {
		lines = append(lines, fmt.Sprintf("Last updated: %s", s.GeneratedAt), "")
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
	lines = append(lines, "Run from `components/server`:", "", "```bash", "SKYFORGE_E2E_DEPLOY=true \\")
	lines = append(lines, "SKYFORGE_E2E_SSH_PROBE_MODE=api \\")
	lines = append(lines, "SKYFORGE_E2E_DEVICE_SET=all \\")
	lines = append(lines, "go run ./cmd/e2echeck --run-generated", "```", "")
	lines = append(lines, "Notes:", "- `SKYFORGE_E2E_SSH_PROBE_MODE=api` uses Skyforge’s `/api/admin/e2e/sshprobe` endpoint (fast, no dependency on a running Forward collector).")
	lines = append(lines, "- If a device fails, inspect its `ws-e2e-*` namespace and the `clabernetes-launcher-*` logs first.", "")

	return strings.Join(lines, "\n")
}
