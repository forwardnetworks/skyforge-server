package skyforge

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"encore.dev/beta/errs"
)

type ListForwardNetworksRequest struct {
	CredentialID string `query:"credentialId"`
}

type ForwardNetworkSummary struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type ListForwardNetworksResponse struct {
	Networks []ForwardNetworkSummary `json:"networks"`
}

// ListForwardNetworks lists Forward networks visible to the caller using either:
// - the requested credentialId (must be user-owned Forward credentials), or
// - the caller's defaultForwardCredentialId in /api/user/settings.
//
//encore:api auth method=GET path=/api/forward/networks
func (s *Service) ListForwardNetworks(ctx context.Context, req *ListForwardNetworksRequest) (*ListForwardNetworksResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}

	credID := strings.TrimSpace(req.CredentialID)
	if credID == "" {
		ctxReq, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		defer cancel()
		rec, err := getUserSettings(ctxReq, s.db, user.Username)
		if err == nil && rec != nil {
			credID = strings.TrimSpace(rec.DefaultForwardCredentialID)
		}
	}
	if credID == "" {
		return &ListForwardNetworksResponse{Networks: []ForwardNetworkSummary{}}, nil
	}

	box := newSecretBox(s.cfg.SessionSecret)
	ctxReq, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	set, err := getUserForwardCredentialSet(ctxReq, s.db, box, user.Username, credID)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load Forward credential set").Err()
	}
	if set == nil {
		return nil, errs.B().Code(errs.NotFound).Msg("credential set not found").Err()
	}
	cfg := set.toForwardClientCreds()
	if strings.TrimSpace(cfg.BaseURL) == "" {
		cfg.BaseURL = defaultForwardBaseURL
	}
	if strings.TrimSpace(cfg.Username) == "" || strings.TrimSpace(cfg.Password) == "" {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg("Forward credentials are missing username/password").Err()
	}

	client, err := newForwardClient(cfg)
	if err != nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid Forward config").Err()
	}

	resp, body, err := client.doJSON(ctxReq, http.MethodGet, "/api/networks", url.Values{}, nil)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to reach Forward").Err()
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, errs.B().Code(errs.Unavailable).Msg("Forward list networks failed").Err()
	}

	out := []ForwardNetworkSummary{}
	var payload any
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("invalid Forward response").Err()
	}

	decodeList := func(raw any) {
		switch v := raw.(type) {
		case []any:
			for _, item := range v {
				buf, _ := json.Marshal(item)
				var n forwardNetwork
				if json.Unmarshal(buf, &n) == nil {
					id := strings.TrimSpace(n.ID)
					if id == "" {
						continue
					}
					out = append(out, ForwardNetworkSummary{
						ID:   id,
						Name: strings.TrimSpace(n.Name),
					})
				}
			}
		}
	}

	switch v := payload.(type) {
	case []any:
		decodeList(v)
	case map[string]any:
		// Be tolerant of wrapper payloads.
		for _, key := range []string{"networks", "items", "data"} {
			if raw, ok := v[key]; ok {
				decodeList(raw)
				if len(out) > 0 {
					break
				}
			}
		}
	}

	return &ListForwardNetworksResponse{Networks: out}, nil
}
