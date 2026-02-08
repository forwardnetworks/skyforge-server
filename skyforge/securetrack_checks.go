package skyforge

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

//go:embed securetrack_assets/checks/*
var secureTrackAssets embed.FS

var (
	secureTrackCatalogOnce sync.Once
	secureTrackCatalog     *SecureTrackCatalog
	secureTrackCatalogErr  error

	secureTrackPacksOnce sync.Once
	secureTrackPacks     *SecureTrackPacks
	secureTrackPacksErr  error
)

func loadSecureTrackCatalog() (*SecureTrackCatalog, error) {
	secureTrackCatalogOnce.Do(func() {
		b, err := fs.ReadFile(secureTrackAssets, "securetrack_assets/checks/catalog.yaml")
		if err != nil {
			secureTrackCatalogErr = err
			return
		}
		var cat SecureTrackCatalog
		if err := yaml.Unmarshal(b, &cat); err != nil {
			secureTrackCatalogErr = err
			return
		}
		secureTrackCatalog = &cat
	})
	return secureTrackCatalog, secureTrackCatalogErr
}

type secureTrackCatalogParamYAML struct {
	Name        string `yaml:"name"`
	Type        string `yaml:"type"`
	Default     any    `yaml:"default,omitempty"`
	Description string `yaml:"description,omitempty"`
	Required    bool   `yaml:"required,omitempty"`
}

func (p *SecureTrackCatalogParam) UnmarshalYAML(value *yaml.Node) error {
	var tmp secureTrackCatalogParamYAML
	if err := value.Decode(&tmp); err != nil {
		return err
	}
	p.Name = strings.TrimSpace(tmp.Name)
	p.Type = strings.TrimSpace(tmp.Type)
	p.Description = strings.TrimSpace(tmp.Description)
	p.Required = tmp.Required
	if tmp.Default == nil {
		p.Default = nil
		return nil
	}
	b, err := json.Marshal(tmp.Default)
	if err != nil {
		return err
	}
	p.Default = b
	return nil
}

func loadSecureTrackPacks() (*SecureTrackPacks, error) {
	secureTrackPacksOnce.Do(func() {
		b, err := fs.ReadFile(secureTrackAssets, "securetrack_assets/checks/packs.yaml")
		if err != nil {
			secureTrackPacksErr = err
			return
		}
		var packs SecureTrackPacks
		if err := yaml.Unmarshal(b, &packs); err != nil {
			secureTrackPacksErr = err
			return
		}
		secureTrackPacks = &packs
	})
	return secureTrackPacks, secureTrackPacksErr
}

type secureTrackPackCheckYAML struct {
	ID         string         `yaml:"id"`
	Parameters map[string]any `yaml:"parameters,omitempty"`
}

func (p *SecureTrackPackCheck) UnmarshalYAML(value *yaml.Node) error {
	var tmp secureTrackPackCheckYAML
	if err := value.Decode(&tmp); err != nil {
		return err
	}
	p.ID = strings.TrimSpace(tmp.ID)
	if tmp.Parameters == nil {
		p.Parameters = nil
		return nil
	}
	converted, err := toJSONMap(tmp.Parameters)
	if err != nil {
		return err
	}
	p.Parameters = converted
	return nil
}

func secureTrackListNQEFiles() ([]string, error) {
	matches, err := fs.Glob(secureTrackAssets, "securetrack_assets/checks/*.nqe")
	if err != nil {
		return nil, err
	}
	var out []string
	for _, m := range matches {
		out = append(out, path.Base(m))
	}
	sort.Strings(out)
	return out, nil
}

func secureTrackReadNQE(checkID string) (string, error) {
	checkID = strings.TrimSpace(checkID)
	if checkID == "" {
		return "", fmt.Errorf("checkId is required")
	}
	// Only allow embedded, flat files.
	if strings.Contains(checkID, "/") || strings.Contains(checkID, "..") {
		return "", fmt.Errorf("invalid checkId")
	}
	if !strings.HasSuffix(strings.ToLower(checkID), ".nqe") {
		checkID += ".nqe"
	}
	b, err := fs.ReadFile(secureTrackAssets, "securetrack_assets/checks/"+checkID)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func secureTrackCatalogDefaultsFor(checkID string) JSONMap {
	cat, err := loadSecureTrackCatalog()
	if err != nil || cat == nil {
		return nil
	}
	checkID = strings.TrimSpace(checkID)
	if checkID == "" {
		return nil
	}
	if !strings.HasSuffix(strings.ToLower(checkID), ".nqe") {
		checkID += ".nqe"
	}
	for _, chk := range cat.Checks {
		if strings.TrimSpace(chk.ID) != checkID {
			continue
		}
		out := JSONMap{}
		for _, p := range chk.Params {
			if strings.TrimSpace(p.Name) == "" || len(p.Default) == 0 {
				continue
			}
			out[p.Name] = p.Default
		}
		return out
	}
	return nil
}

func secureTrackNormalizeNQEResponse(body []byte) (*SecureTrackNQEResponse, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil {
		return nil, err
	}

	var snapshotID string
	if raw, ok := obj["snapshotId"]; ok && len(raw) > 0 {
		_ = json.Unmarshal(raw, &snapshotID)
		snapshotID = strings.TrimSpace(snapshotID)
	}

	total := 0
	if raw, ok := obj["total"]; ok && len(raw) > 0 {
		_ = json.Unmarshal(raw, &total)
	}
	if total == 0 {
		if raw, ok := obj["totalNumItems"]; ok && len(raw) > 0 {
			_ = json.Unmarshal(raw, &total)
		}
	}

	results := json.RawMessage("[]")
	if raw, ok := obj["results"]; ok && len(raw) > 0 {
		results = raw
	} else if raw, ok := obj["items"]; ok && len(raw) > 0 {
		results = raw
	}

	return &SecureTrackNQEResponse{
		SnapshotID: snapshotID,
		Total:      total,
		Results:    results,
	}, nil
}
