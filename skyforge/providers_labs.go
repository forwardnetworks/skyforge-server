package skyforge

import (
	"context"
	"log"
	"strings"
	"time"
)

type labsProvider struct {
	name       string
	publicOnly bool
	list       func(ctx context.Context, cfg Config, query ProviderQuery) ([]LabSummary, map[string]any, error)
	launchURL  func(cfg Config) string
}

func labProvidersForQuery(cfg Config, query ProviderQuery) []labsProvider {
	out := make([]labsProvider, 0, 3)

	out = append(out, labsProvider{
		name:       "eve-ng",
		publicOnly: false,
		launchURL: func(cfg Config) string {
			return cfg.Labs.PublicURL
		},
		list: func(ctx context.Context, cfg Config, query ProviderQuery) ([]LabSummary, map[string]any, error) {
			return listEveLabs(ctx, cfg, EveLabQuery{
				Owner:        query.Owner,
				Mode:         query.Mode,
				OnlyProvider: "eve-ng",
				EveServer:    query.EveServer,
			})
		},
	})

	out = append(out, labsProvider{
		name:       "netlab",
		publicOnly: true,
		list: func(ctx context.Context, cfg Config, query ProviderQuery) ([]LabSummary, map[string]any, error) {
			server, _ := resolveNetlabServer(cfg, query.NetlabServer)
			netlabCfg := cfg.Netlab
			if server != nil {
				netlabCfg = netlabConfigFromServer(*server, cfg.Netlab)
			}
			return listNetlabLabs(ctx, cfg, netlabCfg, query.Owner, query.Mode)
		},
	})

	out = append(out, labsProvider{
		name:       "semaphore",
		publicOnly: true,
		list: func(ctx context.Context, cfg Config, query ProviderQuery) ([]LabSummary, map[string]any, error) {
			return listSemaphoreLabs(ctx, cfg, query.Owner, query.Mode)
		},
	})

	if strings.TrimSpace(query.OnlyProvider) == "" {
		return out
	}

	filtered := make([]labsProvider, 0, len(out))
	for _, provider := range out {
		if strings.EqualFold(provider.name, query.OnlyProvider) {
			filtered = append(filtered, provider)
		}
	}
	return filtered
}

func normalizeLabSummaries(provider, launchURL string, items []LabSummary) []LabSummary {
	now := time.Now().UTC().Format(time.RFC3339)
	if launchURL == "" && provider == "eve-ng" {
		launchURL = "/labs/"
	}
	for i := range items {
		if strings.TrimSpace(items[i].Provider) == "" {
			items[i].Provider = provider
		}
		if strings.TrimSpace(items[i].Status) == "" {
			items[i].Status = "unknown"
		}
		if strings.TrimSpace(items[i].UpdatedAt) == "" {
			items[i].UpdatedAt = now
		}
		if strings.TrimSpace(items[i].LaunchURL) == "" && launchURL != "" {
			items[i].LaunchURL = launchURL
		}
	}
	return items
}

func appendLabSource(sources []LabSource, source map[string]any) []LabSource {
	meta, err := toJSONMap(source)
	if err != nil {
		log.Printf("lab sources encode: %v", err)
		meta = nil
	}
	return append(sources, LabSource{
		Provider:  firstString(source, "provider"),
		Mode:      firstString(source, "mode"),
		Transport: firstString(source, "transport"),
		Endpoint:  firstString(source, "endpoint"),
		Meta:      meta,
	})
}

