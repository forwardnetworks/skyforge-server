package taskengine

import (
	"testing"
	"time"
)

func TestResolveClabernetesSchedulingMode(t *testing.T) {
	topologySmall := `
topology:
  nodes:
    r1: { kind: vr-n9kv }
    r2: { kind: vr-n9kv }
`
	topologyLarge := `
topology:
  nodes:
    r1: { kind: vr-n9kv }
    r2: { kind: vr-n9kv }
    r3: { kind: vr-n9kv }
    r4: { kind: vr-n9kv }
    r5: { kind: vr-n9kv }
`

	tests := []struct {
		name       string
		env        map[string]string
		topology   string
		wantMode   string
		wantReason string
	}{
		{
			name:       "explicit-pack",
			env:        map[string]string{"SKYFORGE_CLABERNETES_SCHEDULING_MODE": "pack"},
			topology:   topologyLarge,
			wantMode:   "pack",
			wantReason: "explicit",
		},
		{
			name:       "explicit-spread",
			env:        map[string]string{"SKYFORGE_CLABERNETES_SCHEDULING_MODE": "spread"},
			topology:   topologySmall,
			wantMode:   "spread",
			wantReason: "explicit",
		},
		{
			name:       "adaptive-small-default-threshold",
			env:        map[string]string{"SKYFORGE_CLABERNETES_SCHEDULING_MODE": "adaptive"},
			topology:   topologySmall,
			wantMode:   "pack",
			wantReason: "adaptive",
		},
		{
			name:       "adaptive-large-default-threshold",
			env:        map[string]string{"SKYFORGE_CLABERNETES_SCHEDULING_MODE": "adaptive"},
			topology:   topologyLarge,
			wantMode:   "spread",
			wantReason: "adaptive",
		},
		{
			name:       "unset-mode-default-adaptive",
			env:        map[string]string{},
			topology:   topologySmall,
			wantMode:   "pack",
			wantReason: "default-adaptive",
		},
		{
			name:       "adaptive-custom-threshold",
			env:        map[string]string{"SKYFORGE_CLABERNETES_ADAPTIVE_PACK_MAX_NODES": "6"},
			topology:   topologyLarge,
			wantMode:   "pack",
			wantReason: "default-adaptive",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotMode, gotReason, _ := resolveClabernetesSchedulingMode(tc.env, tc.topology)
			if gotMode != tc.wantMode {
				t.Fatalf("mode: got=%q want=%q", gotMode, tc.wantMode)
			}
			if gotReason != tc.wantReason {
				t.Fatalf("reason: got=%q want=%q", gotReason, tc.wantReason)
			}
		})
	}
}

func TestForwardSSHProbeConfigFromEnv(t *testing.T) {
	cfg := forwardSSHProbeConfigFromEnv(nil)
	if cfg.DialTimeout != 4*time.Second {
		t.Fatalf("default dial timeout: got=%s want=4s", cfg.DialTimeout)
	}
	if cfg.ReadTimeout != 4*time.Second {
		t.Fatalf("default read timeout: got=%s want=4s", cfg.ReadTimeout)
	}
	if cfg.Consecutive != 1 {
		t.Fatalf("default consecutive: got=%d want=1", cfg.Consecutive)
	}

	cfg = forwardSSHProbeConfigFromEnv(map[string]string{
		"SKYFORGE_FORWARD_SSH_PROBE_DIAL_TIMEOUT_MS": "6500",
		"SKYFORGE_FORWARD_SSH_PROBE_READ_TIMEOUT_MS": "7200",
		"SKYFORGE_FORWARD_SSH_PROBE_CONSECUTIVE":     "3",
	})
	if cfg.DialTimeout != 6500*time.Millisecond {
		t.Fatalf("env dial timeout: got=%s want=6.5s", cfg.DialTimeout)
	}
	if cfg.ReadTimeout != 7200*time.Millisecond {
		t.Fatalf("env read timeout: got=%s want=7.2s", cfg.ReadTimeout)
	}
	if cfg.Consecutive != 3 {
		t.Fatalf("env consecutive: got=%d want=3", cfg.Consecutive)
	}

	cfg = forwardSSHProbeConfigFromEnv(map[string]string{
		"SKYFORGE_FORWARD_SSH_PROBE_DIAL_TIMEOUT_MS": "1",
		"SKYFORGE_FORWARD_SSH_PROBE_READ_TIMEOUT_MS": "999999",
		"SKYFORGE_FORWARD_SSH_PROBE_CONSECUTIVE":     "999",
	})
	if cfg.DialTimeout != 500*time.Millisecond {
		t.Fatalf("clamped dial timeout: got=%s want=500ms", cfg.DialTimeout)
	}
	if cfg.ReadTimeout != 30*time.Second {
		t.Fatalf("clamped read timeout: got=%s want=30s", cfg.ReadTimeout)
	}
	if cfg.Consecutive != 5 {
		t.Fatalf("clamped consecutive: got=%d want=5", cfg.Consecutive)
	}
}
