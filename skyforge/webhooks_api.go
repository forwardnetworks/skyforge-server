package skyforge

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"encore.dev/beta/errs"
	"encore.dev/rlog"
)

type webhookTokenRecord struct {
	Token     string
	UpdatedAt time.Time
}

func (s *Service) getWebhookToken(ctx context.Context, username string) (*webhookTokenRecord, error) {
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	if s.box == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("encryption unavailable").Err()
	}
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("username is required").Err()
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	var tokenEnc string
	var updatedAt time.Time
	err := s.db.QueryRowContext(ctx, `SELECT token, updated_at FROM sf_webhook_tokens WHERE username=$1`, username).Scan(&tokenEnc, &updatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	token, err := s.box.decrypt(tokenEnc)
	if err != nil {
		s.deleteWebhookToken(ctx, username)
		return nil, nil
	}
	return &webhookTokenRecord{Token: strings.TrimSpace(token), UpdatedAt: updatedAt}, nil
}

func (s *Service) deleteWebhookToken(ctx context.Context, username string) {
	if s.db == nil {
		return
	}
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	_, _ = s.db.ExecContext(ctx, `DELETE FROM sf_webhook_tokens WHERE username=$1`, username)
}

func (s *Service) putWebhookToken(ctx context.Context, username, token string) error {
	if s.db == nil {
		return errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	if s.box == nil {
		return errs.B().Code(errs.Unavailable).Msg("encryption unavailable").Err()
	}
	username = strings.ToLower(strings.TrimSpace(username))
	token = strings.TrimSpace(token)
	if username == "" || token == "" {
		return errs.B().Code(errs.InvalidArgument).Msg("username and token are required").Err()
	}
	enc, err := s.box.encrypt(token)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	_, err = s.db.ExecContext(ctx, `INSERT INTO sf_webhook_tokens (username, token, updated_at)
VALUES ($1,$2,now())
ON CONFLICT (username) DO UPDATE SET token=excluded.token, updated_at=now()`, username, enc)
	return err
}

func generateOpaqueToken(bytes int) (string, error) {
	b := make([]byte, bytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

type WebhookTokenResponse struct {
	Token         string `json:"token"`
	IngestBaseURL string `json:"ingestBaseUrl"`
	UpdatedAt     string `json:"updatedAt,omitempty"`
}

// GetWebhookToken returns the per-user webhook ingest token.
//
//encore:api auth method=GET path=/api/webhooks/token
func (s *Service) GetWebhookToken(ctx context.Context) (*WebhookTokenResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	rec, err := s.getWebhookToken(ctx, user.Username)
	if err != nil {
		rlog.Error("failed to load webhook token", "username", user.Username, "error", err)
		return nil, errs.B().Code(errs.Internal).Msg("failed to load webhook token").Err()
	}
	if rec == nil || rec.Token == "" {
		token, err := generateOpaqueToken(16)
		if err != nil {
			return nil, errs.B().Code(errs.Internal).Msg("failed to generate token").Err()
		}
		if err := s.putWebhookToken(ctx, user.Username, token); err != nil {
			return nil, errs.B().Code(errs.Internal).Msg("failed to store token").Err()
		}
		rec = &webhookTokenRecord{Token: token, UpdatedAt: time.Now().UTC()}
	}
	return &WebhookTokenResponse{
		Token:         rec.Token,
		IngestBaseURL: strings.TrimRight(s.cfg.PublicURL, "/") + "/hooks/" + rec.Token,
		UpdatedAt:     rec.UpdatedAt.UTC().Format(time.RFC3339),
	}, nil
}

// RotateWebhookToken rotates the per-user webhook ingest token (invalidates the old one).
//
//encore:api auth method=POST path=/api/webhooks/token/rotate
func (s *Service) RotateWebhookToken(ctx context.Context) (*WebhookTokenResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	token, err := generateOpaqueToken(16)
	if err != nil {
		return nil, errs.B().Code(errs.Internal).Msg("failed to generate token").Err()
	}
	if err := s.putWebhookToken(ctx, user.Username, token); err != nil {
		return nil, errs.B().Code(errs.Internal).Msg("failed to store token").Err()
	}
	return &WebhookTokenResponse{
		Token:         token,
		IngestBaseURL: strings.TrimRight(s.cfg.PublicURL, "/") + "/hooks/" + token,
		UpdatedAt:     time.Now().UTC().Format(time.RFC3339),
	}, nil
}

type WebhookEvent struct {
	ID         int64     `json:"id"`
	ReceivedAt time.Time `json:"receivedAt"`
	Method     string    `json:"method"`
	Path       string    `json:"path"`
	SourceIP   string    `json:"sourceIp,omitempty"`
	Body       string    `json:"body,omitempty"`
}

type WebhookEventsParams struct {
	Limit    string `query:"limit" encore:"optional"`
	BeforeID string `query:"before_id" encore:"optional"`
}

type WebhookEventsResponse struct {
	Events []WebhookEvent `json:"events"`
}

// ListWebhookEvents returns the current user's webhook inbox.
//
//encore:api auth method=GET path=/api/webhooks/events
func (s *Service) ListWebhookEvents(ctx context.Context, params *WebhookEventsParams) (*WebhookEventsResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("webhook store unavailable").Err()
	}
	limit := int64(200)
	if params != nil && strings.TrimSpace(params.Limit) != "" {
		if v, err := strconv.ParseInt(strings.TrimSpace(params.Limit), 10, 64); err == nil && v > 0 && v <= 1000 {
			limit = v
		}
	}
	var beforeID *int64
	if params != nil && strings.TrimSpace(params.BeforeID) != "" {
		if v, err := strconv.ParseInt(strings.TrimSpace(params.BeforeID), 10, 64); err == nil && v > 0 {
			beforeID = &v
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	query := `SELECT id, received_at, method, path, COALESCE(source_ip::text,''), COALESCE(body,'') FROM sf_webhook_events WHERE username=$1`
	args := []any{strings.ToLower(user.Username)}
	if beforeID != nil {
		query += ` AND id < $2`
		args = append(args, *beforeID)
	}
	query += ` ORDER BY id DESC LIMIT ` + strconv.FormatInt(limit, 10)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		rlog.Error("failed to query webhook events", "username", user.Username, "error", err)
		return nil, errs.B().Code(errs.Internal).Msg("failed to query webhook events").Err()
	}
	defer rows.Close()

	out := make([]WebhookEvent, 0, limit)
	for rows.Next() {
		var ev WebhookEvent
		var src, body string
		if err := rows.Scan(&ev.ID, &ev.ReceivedAt, &ev.Method, &ev.Path, &src, &body); err != nil {
			return nil, errs.B().Code(errs.Internal).Msg("failed to read webhook event").Err()
		}
		ev.Method = strings.ToUpper(strings.TrimSpace(ev.Method))
		ev.Path = strings.TrimSpace(ev.Path)
		ev.SourceIP = strings.TrimSpace(src)
		ev.Body = body
		out = append(out, ev)
	}
	if err := rows.Err(); err != nil {
		return nil, errs.B().Code(errs.Internal).Msg("failed to read webhook events").Err()
	}
	return &WebhookEventsResponse{Events: out}, nil
}

func resolveWebhookTokenFromPath(path string) (string, string) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", ""
	}
	path = strings.TrimPrefix(path, "/")
	parts := strings.SplitN(path, "/", 3)
	if len(parts) < 2 || parts[0] != "hooks" {
		return "", ""
	}
	token := strings.TrimSpace(parts[1])
	rest := "/"
	if len(parts) == 3 && strings.TrimSpace(parts[2]) != "" {
		rest = "/" + parts[2]
	}
	return token, rest
}

func requestSourceIP(r *http.Request) net.IP {
	if r == nil {
		return nil
	}
	if xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); xff != "" {
		first := strings.TrimSpace(strings.Split(xff, ",")[0])
		if ip := net.ParseIP(first); ip != nil {
			return ip
		}
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err == nil {
		return net.ParseIP(host)
	}
	return net.ParseIP(strings.TrimSpace(r.RemoteAddr))
}

func (s *Service) lookupWebhookUserByToken(ctx context.Context, token string) (string, error) {
	if s.db == nil {
		return "", errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	if s.box == nil {
		return "", errs.B().Code(errs.Unavailable).Msg("encryption unavailable").Err()
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return "", errs.B().Code(errs.InvalidArgument).Msg("token is required").Err()
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	rows, err := s.db.QueryContext(ctx, `SELECT username, token FROM sf_webhook_tokens`)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	for rows.Next() {
		var username, tokenEnc string
		if err := rows.Scan(&username, &tokenEnc); err != nil {
			return "", err
		}
		plain, err := s.box.decrypt(tokenEnc)
		if err != nil {
			continue
		}
		if subtleConstantTimeEqual(strings.TrimSpace(plain), token) {
			return strings.TrimSpace(username), nil
		}
	}
	return "", sql.ErrNoRows
}

func subtleConstantTimeEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := 0; i < len(a); i++ {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

// WebhookIngestAny receives webhook events via tokenized URLs.
//
// Example:
//
//	POST https://<hostname>/hooks/<token>/github
//
//encore:api public raw method=POST path=/hooks/*rest
func (s *Service) WebhookIngestAny(w http.ResponseWriter, req *http.Request) {
	if req == nil {
		errs.HTTPError(w, errs.B().Code(errs.InvalidArgument).Msg("invalid request").Err())
		return
	}
	token, rest := resolveWebhookTokenFromPath(req.URL.Path)
	if token == "" {
		errs.HTTPError(w, errs.B().Code(errs.NotFound).Msg("invalid webhook path").Err())
		return
	}

	username, err := s.lookupWebhookUserByToken(req.Context(), token)
	if err != nil {
		errs.HTTPError(w, errs.B().Code(errs.Unauthenticated).Msg("invalid webhook token").Err())
		return
	}

	bodyBytes, _ := io.ReadAll(io.LimitReader(req.Body, 1<<20))
	_ = req.Body.Close()

	headers := map[string]string{}
	for k, v := range req.Header {
		if len(v) == 0 {
			continue
		}
		headers[k] = v[0]
	}
	headersJSON, _ := json.Marshal(headers)

	srcIP := requestSourceIP(req)
	_, dbErr := s.db.ExecContext(req.Context(), `
INSERT INTO sf_webhook_events (username, token, method, path, source_ip, headers_json, body)
VALUES ($1,$2,$3,$4,$5,$6,$7)
`, strings.ToLower(username), token, req.Method, rest, srcIP, string(headersJSON), string(bodyBytes))
	if dbErr != nil {
		errs.HTTPError(w, errs.B().Code(errs.Internal).Msg("failed to store webhook").Err())
		return
	}
	// Best-effort update signal for UI streaming (SSE).
	_ = notifyWebhookUpdatePG(req.Context(), s.db, username)

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}
