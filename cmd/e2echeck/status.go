package main

import (
	"bufio"
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

	VXLAN    string `json:"vxlan,omitempty"`    // pass|fail|skip|unknown
	K8sNodes int    `json:"k8sNodes,omitempty"` // number of k8s nodes spanned by the topology (when known)
}

type e2eStatusRecorder struct {
	jsonPath string
	mdPath   string
	state    e2eStatusFile
}

// syncFromRunlog best-effort rebuilds per-device status from the persisted JSONL run log.
// This makes the status file resilient if a prior e2echeck run was interrupted between
// writing the run log and flushing the status summary.
func (r *e2eStatusRecorder) syncFromRunlog(runlogPath string) {
	if r == nil {
		return
	}
	runlogPath = strings.TrimSpace(runlogPath)
	if runlogPath == "" {
		return
	}
	f, err := os.Open(runlogPath)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()

	type entry struct {
		At        string `json:"at"`
		Device    string `json:"device"`
		Template  string `json:"template"`
		DeployTyp string `json:"deployType"`
		TaskID    int    `json:"taskId"`
		VXLAN     string `json:"vxlan"`
		K8sNodes  int    `json:"k8sNodes"`
		Status    string `json:"status"`
		Error     string `json:"error"`
		Notes     string `json:"notes"`
	}

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		ln := strings.TrimSpace(sc.Text())
		if ln == "" {
			continue
		}
		var e entry
		if err := json.Unmarshal([]byte(ln), &e); err != nil {
			continue
		}
		dev := strings.TrimSpace(e.Device)
		if dev == "" {
			continue
		}
		st := strings.ToLower(strings.TrimSpace(e.Status))
		if st != "pass" && st != "fail" && st != "skip" {
			continue
		}
		// Skip entries are often emitted when a device was filtered out for a given
		// run (e.g. SKYFORGE_E2E_DEVICES). They should not overwrite the last-known
		// pass/fail status for a device.
		if st == "skip" {
			continue
		}

		at := strings.TrimSpace(e.At)
		if at == "" {
			at = time.Now().UTC().Format(time.RFC3339)
		}
		prev := r.state.Devices[dev]

		// VXLAN smoke failures should not override "deploy + SSH reachability" status.
		// They are tracked in the dedicated VXLAN column.
		vxlanOnlyFailure := st == "fail" && strings.EqualFold(strings.TrimSpace(e.Notes), "vxlan smoke failed")

		next := prev
		next.Device = dev
		next.UpdatedAt = at
		if strings.TrimSpace(e.Template) != "" {
			next.Template = strings.TrimSpace(e.Template)
		}
		if strings.TrimSpace(e.DeployTyp) != "" {
			next.DeployType = strings.TrimSpace(e.DeployTyp)
		}
		if e.TaskID != 0 {
			next.TaskID = e.TaskID
		}
		if strings.TrimSpace(e.VXLAN) != "" {
			next.VXLAN = strings.TrimSpace(e.VXLAN)
		}
		if e.K8sNodes > 0 {
			next.K8sNodes = e.K8sNodes
		}

		switch st {
		case "pass":
			next.Status = "pass"
			next.LastOKAt = at
			next.LastError = ""
			next.Error = ""
			next.Notes = strings.TrimSpace(e.Notes)
		case "skip":
			next.Status = "skip"
			next.Error = ""
			next.Notes = strings.TrimSpace(e.Notes)
		case "fail":
			if vxlanOnlyFailure {
				// Preserve previous deploy status; annotate with VXLAN failure detail.
				if strings.TrimSpace(next.VXLAN) == "" {
					next.VXLAN = "fail"
				}
				msg := strings.TrimSpace(e.Error)
				if msg == "" {
					msg = "vxlan smoke failed"
				}
				next.Error = ""
				next.Notes = "vxlan smoke failed: " + msg
			} else {
				next.Status = "fail"
				next.LastFailAt = at
				next.LastError = strings.TrimSpace(e.Error)
				next.Error = strings.TrimSpace(e.Error)
				next.Notes = strings.TrimSpace(e.Notes)
			}
		}

		r.state.Devices[dev] = next
	}
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

func (r *e2eStatusRecorder) update(device string, status string, template string, deployType string, taskID int, errMsg string, notes string, vxlan string, k8sNodes int) {
	if r == nil {
		return
	}
	device = strings.TrimSpace(device)
	if device == "" {
		return
	}
	// Skip updates are typically emitted when a device was filtered out for a
	// given run. Don't let that clobber the last-known pass/fail status.
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "skip", "skipped":
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
		VXLAN:      prev.VXLAN,
		K8sNodes:   prev.K8sNodes,
	}
	if strings.TrimSpace(vxlan) != "" {
		st.VXLAN = strings.TrimSpace(vxlan)
		st.K8sNodes = k8sNodes
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
		st := r.state.Devices[d]
		// Older versions of e2echeck wrote "skip" entries when a device was filtered
		// out, even if it had never been run. Normalize those to "unknown" so the
		// status table remains a "last known result" view.
		if strings.EqualFold(strings.TrimSpace(st.Status), "skip") &&
			strings.TrimSpace(st.LastOKAt) == "" &&
			strings.TrimSpace(st.LastFailAt) == "" {
			st.Status = "unknown"
			if strings.TrimSpace(st.Notes) == "" || strings.Contains(strings.ToLower(st.Notes), "skipped by") {
				st.Notes = "not yet run"
			}
		}
		// Persist any normalization back into the device map; the markdown renderer
		// uses r.state.Devices (not rows).
		r.state.Devices[d] = st
		rows = append(rows, st)
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
	lines = append(lines, "Coverage: baseline **deploy + SSH reachability + VXLAN overlay** for each onboarded Netlab device type (netlab-c9s -> clabernetes + vrnetlab hybrid).", "")
	lines = append(lines, "Legend: ✅ pass · ❌ fail · ⏭ skipped · ❔ unknown", "")
	lines = append(lines, "| Device type | Status | VXLAN | Updated | Notes |", "| --- | --- | --- | --- | --- |")

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
		vx := "❔"
		switch strings.ToLower(strings.TrimSpace(st.VXLAN)) {
		case "pass", "ok", "success":
			vx = "✅"
		case "fail", "failed", "error":
			vx = "❌"
		case "skip", "skipped":
			vx = "⏭"
		}
		if vx == "✅" && st.K8sNodes > 0 {
			vx = fmt.Sprintf("✅ (%dn)", st.K8sNodes)
		}
		notes := strings.TrimSpace(st.Notes)
		if notes == "" {
			notes = strings.TrimSpace(st.Error)
		}
		notes = strings.ReplaceAll(notes, "\n", " ")
		lines = append(lines, fmt.Sprintf("| `%s` | %s | %s | %s | %s |", d, icon, vx, strings.TrimSpace(st.UpdatedAt), notes))
	}
	lines = append(lines, "")
	lines = append(lines, "## How to run", "")
	lines = append(lines, "Run from `skyforge-server`:", "", "```bash", "SKYFORGE_E2E_DEPLOY=true \\")
	lines = append(lines, "SKYFORGE_E2E_SSH_PROBE_MODE=api \\")
	lines = append(lines, "SKYFORGE_E2E_DEVICE_SET=all \\")
	lines = append(lines, "go run ./cmd/e2echeck --run-generated", "```", "")
	lines = append(lines, "Notes:", "- `SKYFORGE_E2E_SSH_PROBE_MODE=api` uses Skyforge’s `/api/admin/e2e/sshprobe` endpoint (fast, no dependency on a running Forward collector).")
	lines = append(lines, "- If a device fails, inspect its `ws-e2e-*` namespace and the `clabernetes-launcher-*` logs first.", "")

	return strings.Join(lines, "\n")
}
