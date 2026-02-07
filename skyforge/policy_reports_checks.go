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

//go:embed policy_reports_assets/checks/*
var policyReportsAssets embed.FS

var (
	policyReportsCatalogOnce sync.Once
	policyReportsCatalog     *PolicyReportCatalog
	policyReportsCatalogErr  error

	policyReportsPacksOnce sync.Once
	policyReportsPacks     *PolicyReportPacks
	policyReportsPacksErr  error
)

func loadPolicyReportCatalog() (*PolicyReportCatalog, error) {
	policyReportsCatalogOnce.Do(func() {
		b, err := fs.ReadFile(policyReportsAssets, "policy_reports_assets/checks/catalog.yaml")
		if err != nil {
			policyReportsCatalogErr = err
			return
		}
		var cat PolicyReportCatalog
		if err := yaml.Unmarshal(b, &cat); err != nil {
			policyReportsCatalogErr = err
			return
		}
		policyReportsCatalog = &cat
	})
	return policyReportsCatalog, policyReportsCatalogErr
}

type policyReportsCatalogParamYAML struct {
	Name        string `yaml:"name"`
	Type        string `yaml:"type"`
	Default     any    `yaml:"default,omitempty"`
	Description string `yaml:"description,omitempty"`
	Required    bool   `yaml:"required,omitempty"`
}

func (p *PolicyReportCatalogParam) UnmarshalYAML(value *yaml.Node) error {
	var tmp policyReportsCatalogParamYAML
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

func loadPolicyReportPacks() (*PolicyReportPacks, error) {
	policyReportsPacksOnce.Do(func() {
		b, err := fs.ReadFile(policyReportsAssets, "policy_reports_assets/checks/packs.yaml")
		if err != nil {
			policyReportsPacksErr = err
			return
		}
		var packs PolicyReportPacks
		if err := yaml.Unmarshal(b, &packs); err != nil {
			policyReportsPacksErr = err
			return
		}
		policyReportsPacks = &packs
	})
	return policyReportsPacks, policyReportsPacksErr
}

type policyReportsPackCheckYAML struct {
	ID         string         `yaml:"id"`
	Parameters map[string]any `yaml:"parameters,omitempty"`
}

func (p *PolicyReportPackCheck) UnmarshalYAML(value *yaml.Node) error {
	var tmp policyReportsPackCheckYAML
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

func policyReportsListNQEFiles() ([]string, error) {
	matches, err := fs.Glob(policyReportsAssets, "policy_reports_assets/checks/*.nqe")
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

func policyReportsReadNQE(checkID string) (string, error) {
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
	b, err := fs.ReadFile(policyReportsAssets, "policy_reports_assets/checks/"+checkID)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func policyReportsCatalogDefaultsFor(checkID string) JSONMap {
	cat, err := loadPolicyReportCatalog()
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

func policyReportsNormalizeNQEResponse(body []byte) (*PolicyReportNQEResponse, error) {
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

	return &PolicyReportNQEResponse{
		SnapshotID: snapshotID,
		Total:      total,
		Results:    results,
	}, nil
}
