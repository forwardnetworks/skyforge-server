package skyforge

import (
	"context"
	"log"
	"strings"
	"time"

	"encore.dev/beta/errs"
)

type ForwardCollectorSummary struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Username string `json:"username"`
}

type ListForwardCollectorsResponse struct {
	Collectors []ForwardCollectorSummary `json:"collectors"`
}

// ListForwardCollectors lists collectors visible to the authenticated user's Forward org.
//
//encore:api auth method=GET path=/api/forward/collectors
func (s *Service) ListForwardCollectors(ctx context.Context) (*ListForwardCollectorsResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	rec, err := getUserForwardCredentials(ctx, s.db, newSecretBox(s.cfg.SessionSecret), user.Username)
	if err != nil {
		log.Printf("forward collectors get creds: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load Forward credentials").Err()
	}
	if rec == nil || strings.TrimSpace(rec.ForwardUsername) == "" || strings.TrimSpace(rec.ForwardPassword) == "" {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg("Forward credentials required").Err()
	}

	client, err := newForwardClient(forwardCredentials{
		BaseURL:       rec.BaseURL,
		SkipTLSVerify: rec.SkipTLSVerify,
		Username:      rec.ForwardUsername,
		Password:      rec.ForwardPassword,
	})
	if err != nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid Forward config").Err()
	}
	collectors, err := forwardListCollectors(ctx, client)
	if err != nil {
		log.Printf("forward list collectors: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to list Forward collectors").Err()
	}
	out := make([]ForwardCollectorSummary, 0, len(collectors))
	for _, c := range collectors {
		id := strings.TrimSpace(c.ID)
		name := strings.TrimSpace(c.Name)
		username := strings.TrimSpace(c.Username)
		if id == "" && username == "" && name == "" {
			continue
		}
		out = append(out, ForwardCollectorSummary{
			ID:       id,
			Name:     name,
			Username: username,
		})
	}
	return &ListForwardCollectorsResponse{Collectors: out}, nil
}
