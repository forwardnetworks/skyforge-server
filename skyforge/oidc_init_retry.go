package skyforge

import (
	"math/rand"
	"time"

	"encore.dev/rlog"
)

func oidcIsConfigured(cfg Config) bool {
	return cfg.OIDC.IssuerURL != "" &&
		cfg.OIDC.ClientID != "" &&
		cfg.OIDC.ClientSecret != "" &&
		cfg.OIDC.RedirectURL != ""
}

func (s *Service) oidcClient() *OIDCClient {
	if s == nil {
		return nil
	}
	return s.oidc.Load()
}

func (s *Service) retryOIDCInit() {
	// Ensure jitter differs across pods.
	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	backoff := 2 * time.Second
	const maxBackoff = 30 * time.Second

	for {
		if s == nil {
			return
		}
		if s.oidc.Load() != nil {
			return
		}

		client, err := initOIDCClient(s.cfg)
		if err == nil && client != nil {
			s.oidc.Store(client)
			rlog.Info("oidc init recovered")
			return
		}

		// Keep trying; if the provider becomes reachable, we can start serving logins
		// without restarting the whole API.
		rlog.Warn("oidc init still failing; will retry", "err", err, "sleep", backoff.String())

		j := time.Duration(r.Int63n(int64(backoff / 3)))
		time.Sleep(backoff + j)
		if backoff < maxBackoff {
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}
}
