package main

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// e2eRunLogger writes one JSON object per line so you can watch progress live and
// retain history across runs without complex merging logic.
type e2eRunLogger struct {
	path string
	mu   sync.Mutex
}

type e2eRunLogEntry struct {
	At          string `json:"at"`
	BaseURL     string `json:"baseUrl"`
	Workspace   string `json:"workspace"`
	WorkspaceID string `json:"workspaceId"`
	Test        string `json:"test"`
	Kind        string `json:"kind"`

	Device     string `json:"device,omitempty"`
	Template   string `json:"template,omitempty"`
	DeployType string `json:"deployType,omitempty"`
	TaskID     int    `json:"taskId,omitempty"`

	VXLAN    string `json:"vxlan,omitempty"`    // pass|fail|skip|unknown
	K8sNodes int    `json:"k8sNodes,omitempty"` // number of k8s nodes spanned by the topology (when known)

	Status string `json:"status"` // pass|fail|skip|info
	Error  string `json:"error,omitempty"`
	Notes  string `json:"notes,omitempty"`
}

func newE2ERunLogger(path string) (*e2eRunLogger, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	return &e2eRunLogger{path: path}, nil
}

func (l *e2eRunLogger) append(e e2eRunLogEntry) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	e.At = time.Now().UTC().Format(time.RFC3339)
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()

	w := bufio.NewWriter(f)
	enc, err := json.Marshal(e)
	if err == nil {
		_, _ = w.Write(enc)
		_, _ = w.WriteString("\n")
	}
	_ = w.Flush()
}
