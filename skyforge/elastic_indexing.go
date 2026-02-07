package skyforge

import (
	"context"
	"strings"
	"time"

	"encore.dev/rlog"

	elasticint "encore.app/integrations/elastic"
)

func (s *Service) elasticIndexingEnabled() bool {
	if s == nil {
		return false
	}
	if !s.cfg.Features.ElasticEnabled {
		return false
	}
	return strings.TrimSpace(s.cfg.Elastic.URL) != ""
}

func (s *Service) getElasticClient() (*elasticint.Client, error) {
	if !s.elasticIndexingEnabled() {
		return nil, nil
	}
	s.elasticOnce.Do(func() {
		s.elasticClient, s.elasticInitErr = elasticint.New(s.cfg.Elastic.URL, s.cfg.Elastic.IndexPrefix)
		if s.elasticInitErr != nil {
			rlog.Error("elastic init failed", "error", s.elasticInitErr)
		}
	})
	if s.elasticInitErr != nil {
		return nil, s.elasticInitErr
	}
	return s.elasticClient, nil
}

// indexElasticAsync is best-effort. It never returns an error to the caller.
func (s *Service) indexElasticAsync(category string, receivedAt time.Time, doc any) {
	if !s.elasticIndexingEnabled() {
		return
	}
	client, err := s.getElasticClient()
	if err != nil || client == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := client.IndexDaily(ctx, category, receivedAt, doc); err != nil {
			rlog.Error("elastic index failed", "category", category, "error", err)
		}
	}()
}
