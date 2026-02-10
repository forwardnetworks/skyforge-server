package trafficassets

import (
	"embed"
	"fmt"
	"io/fs"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed traffic_assets/catalog.yaml traffic_assets/queries/*.nqe
var assets embed.FS

type CatalogQuery struct {
	ID          string `yaml:"id" json:"id"`
	Title       string `yaml:"title,omitempty" json:"title,omitempty"`
	Category    string `yaml:"category,omitempty" json:"category,omitempty"`
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
}

type Catalog struct {
	Version string         `yaml:"version,omitempty" json:"version,omitempty"`
	Queries []CatalogQuery `yaml:"queries,omitempty" json:"queries,omitempty"`
}

func LoadCatalog() (*Catalog, error) {
	b, err := fs.ReadFile(assets, "traffic_assets/catalog.yaml")
	if err != nil {
		return nil, err
	}
	var out Catalog
	if err := yaml.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func ListQueryFiles() ([]string, error) {
	matches, err := fs.Glob(assets, "traffic_assets/queries/*.nqe")
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(matches))
	for _, p := range matches {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, strings.TrimPrefix(p, "traffic_assets/queries/"))
	}
	return out, nil
}

func ReadQuery(queryID string) (string, error) {
	queryID = strings.TrimSpace(queryID)
	if queryID == "" {
		return "", fmt.Errorf("query id is required")
	}
	if !strings.HasSuffix(strings.ToLower(queryID), ".nqe") {
		queryID += ".nqe"
	}
	b, err := fs.ReadFile(assets, "traffic_assets/queries/"+queryID)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
