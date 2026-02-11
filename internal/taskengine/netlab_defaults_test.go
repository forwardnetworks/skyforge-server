package taskengine

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestNetlabDeviceDefaults_NoFallbacks(t *testing.T) {
	var catalog netlabDeviceDefaults
	if err := json.Unmarshal(netlabDeviceDefaultsJSON, &catalog); err != nil {
		t.Fatalf("failed to parse embedded catalog: %v", err)
	}
	if len(catalog.Fallback) != 0 {
		t.Fatalf("expected no fallback credentials, got %d", len(catalog.Fallback))
	}
	if len(catalog.Sets) == 0 {
		t.Fatalf("expected at least one credential set")
	}
	for _, set := range catalog.Sets {
		if set.Device == "" {
			t.Fatalf("expected set device to be non-empty")
		}
		if len(set.Credentials) != 1 {
			t.Fatalf("expected exactly 1 credential for %q, got %d", set.Device, len(set.Credentials))
		}
		cred := set.Credentials[0]
		if cred.Username == "" || cred.Password == "" {
			t.Fatalf("expected non-empty credential for %q", set.Device)
		}
	}
}

func TestNetlabDeviceDefaults_CatalogsInSync(t *testing.T) {
	_, testFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("runtime.Caller failed")
	}
	dir := filepath.Dir(testFile)

	taskPath := filepath.Join(dir, "netlab_device_defaults.json")
	apiPath := filepath.Join(dir, "..", "..", "skyforge", "netlab_device_defaults.json")
	taskData, err := os.ReadFile(taskPath)
	if err != nil {
		t.Fatalf("read %s failed: %v", taskPath, err)
	}
	apiData, err := os.ReadFile(apiPath)
	if err != nil {
		t.Fatalf("read %s failed: %v", apiPath, err)
	}
	if !bytes.Equal(taskData, apiData) {
		t.Fatalf("taskengine and api netlab_device_defaults.json differ; regenerate with go run ./cmd/gennetlabdefaults")
	}
}

func TestNetlabCredentialForDevice_NoFallback(t *testing.T) {
	if _, ok := netlabCredentialForDevice("does-not-exist", ""); ok {
		t.Fatalf("expected lookup for unknown device to return ok=false")
	}
	cred, ok := netlabCredentialForDevice("vmx", "ghcr.io/forwardnetworks/vrnetlab/vr-vmx:18.2R1.9")
	if !ok {
		t.Fatalf("expected vmx lookup ok=true")
	}
	if cred.Username != "admin" || cred.Password != "admin@123" {
		t.Fatalf("unexpected vmx credential: %#v", cred)
	}

	linuxCred, ok := netlabCredentialForDevice("linux", "python:3.12-alpine")
	if !ok {
		t.Fatalf("expected linux lookup ok=true")
	}
	if linuxCred.Username != "root" || linuxCred.Password != "admin" {
		t.Fatalf("unexpected linux credential: %#v", linuxCred)
	}
}
