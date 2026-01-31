package skyforge

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
	"golang.org/x/oauth2"

	"encore.dev/beta/errs"
)

type AITemplateProvider string

const (
	AITemplateProviderGemini AITemplateProvider = "gemini"
)

type AITemplateKind string

const (
	AITemplateKindNetlab      AITemplateKind = "netlab"
	AITemplateKindContainerlab AITemplateKind = "containerlab"
)

type UserAIGenerateRequest struct {
	Provider     AITemplateProvider `json:"provider"`
	Kind         AITemplateKind     `json:"kind"`
	Prompt       string             `json:"prompt"`
	Constraints  []string           `json:"constraints,omitempty"`
	SeedTemplate string             `json:"seedTemplate,omitempty"`

	// Optional model controls.
	MaxOutputTokens int     `json:"maxOutputTokens,omitempty"`
	Temperature     float64 `json:"temperature,omitempty"`
}

type UserAIGenerateResponse struct {
	ID        string   `json:"id"`
	Provider  string   `json:"provider"`
	Kind      string   `json:"kind"`
	Filename  string   `json:"filename"`
	Content   string   `json:"content"`
	Warnings  []string `json:"warnings,omitempty"`
	CreatedAt string   `json:"createdAt"`
}

type UserAIHistoryItem struct {
	ID        string `json:"id"`
	Provider  string `json:"provider"`
	Kind      string `json:"kind"`
	Filename  string `json:"filename"`
	CreatedAt string `json:"createdAt"`
}

type UserAIHistoryResponse struct {
	Items []*UserAIHistoryItem `json:"items"`
}

// GenerateUserAITemplate generates a single-file template using the user's configured AI provider.
//
//encore:api auth method=POST path=/api/user/ai/generate
func (s *Service) GenerateUserAITemplate(ctx context.Context, req *UserAIGenerateRequest) (*UserAIGenerateResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if !s.cfg.AIEnabled {
		return nil, errs.B().Code(errs.NotFound).Msg("AI is disabled").Err()
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	if req == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("request required").Err()
	}

	username := strings.ToLower(strings.TrimSpace(user.Username))
	provider := strings.TrimSpace(string(req.Provider))
	kind := strings.TrimSpace(string(req.Kind))
	prompt := strings.TrimSpace(req.Prompt)
	if provider == "" {
		provider = string(AITemplateProviderGemini)
	}
	if kind != string(AITemplateKindNetlab) && kind != string(AITemplateKindContainerlab) {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid template kind").Err()
	}
	if prompt == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("prompt is required").Err()
	}

	if _, err := s.db.ExecContext(ctx, `INSERT INTO sf_users (username) VALUES ($1) ON CONFLICT (username) DO NOTHING`, username); err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}

	var content string
	var warnings []string
	switch AITemplateProvider(provider) {
	case AITemplateProviderGemini:
		if !s.cfg.GeminiEnabled {
			return nil, errs.B().Code(errs.FailedPrecondition).Msg("Gemini is disabled").Err()
		}
		content, warnings, err = s.generateWithGeminiVertex(ctx, username, req)
		if err != nil {
			return nil, err
		}
	default:
		return nil, errs.B().Code(errs.InvalidArgument).Msg("unsupported provider").Err()
	}

	filename := "topology.yml"
	if kind == string(AITemplateKindContainerlab) {
		filename = "topology.clab.yml"
	}

	id := uuid.New()
	createdAt := time.Now().UTC()
	if warnings == nil {
		warnings = []string{}
	}
	warningsJSON, _ := json.Marshal(warnings)
	if _, err := s.db.ExecContext(ctx, `INSERT INTO sf_user_ai_generations (
  id, username, provider, kind, prompt, content, warnings, created_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		id,
		username,
		provider,
		kind,
		prompt,
		content,
		string(warningsJSON),
		createdAt,
	); err != nil {
		log.Printf("ai generate store (%s): %v", username, err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to store generated template").Err()
	}

	return &UserAIGenerateResponse{
		ID:        id.String(),
		Provider:  provider,
		Kind:      kind,
		Filename:  filename,
		Content:   content,
		Warnings:  warnings,
		CreatedAt: createdAt.Format(time.RFC3339Nano),
	}, nil
}

// GetUserAITemplateHistory lists recent AI generations for the current user.
//
//encore:api auth method=GET path=/api/user/ai/history
func (s *Service) GetUserAITemplateHistory(ctx context.Context) (*UserAIHistoryResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	username := strings.ToLower(strings.TrimSpace(user.Username))
	rows, err := s.db.QueryContext(ctx, `SELECT id, provider, kind, created_at
FROM sf_user_ai_generations
WHERE username=$1
ORDER BY created_at DESC
LIMIT 50`, username)
	if err != nil {
		if isMissingDBRelation(err) {
			return &UserAIHistoryResponse{Items: []*UserAIHistoryItem{}}, nil
		}
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load history").Err()
	}
	defer rows.Close()

	var items []*UserAIHistoryItem
	for rows.Next() {
		var id uuid.UUID
		var provider, kind string
		var createdAt time.Time
		if err := rows.Scan(&id, &provider, &kind, &createdAt); err != nil {
			return nil, errs.B().Code(errs.Unavailable).Msg("failed to load history").Err()
		}
		filename := "topology.yml"
		if kind == string(AITemplateKindContainerlab) {
			filename = "topology.clab.yml"
		}
		items = append(items, &UserAIHistoryItem{
			ID:        id.String(),
			Provider:  provider,
			Kind:      kind,
			Filename:  filename,
			CreatedAt: createdAt.UTC().Format(time.RFC3339Nano),
		})
	}
	return &UserAIHistoryResponse{Items: items}, nil
}

type geminiVertexGenerateRequest struct {
	Contents []struct {
		Role  string `json:"role,omitempty"`
		Parts []struct {
			Text string `json:"text,omitempty"`
		} `json:"parts"`
	} `json:"contents"`
	SystemInstruction *struct {
		Parts []struct {
			Text string `json:"text,omitempty"`
		} `json:"parts"`
	} `json:"systemInstruction,omitempty"`
	GenerationConfig map[string]any `json:"generationConfig,omitempty"`
}

type geminiVertexGenerateResponse struct {
	Candidates []struct {
		Content struct {
			Parts []struct {
				Text string `json:"text,omitempty"`
			} `json:"parts"`
		} `json:"content"`
	} `json:"candidates"`
}

func (s *Service) generateWithGeminiVertex(ctx context.Context, username string, req *UserAIGenerateRequest) (string, []string, error) {
	cfg, err := geminiOAuthConfig(s.cfg)
	if err != nil || cfg == nil {
		return "", nil, errs.B().Code(errs.FailedPrecondition).Msg("Gemini OAuth is not configured").Err()
	}
	if strings.TrimSpace(s.cfg.GeminiProjectID) == "" {
		return "", nil, errs.B().Code(errs.FailedPrecondition).Msg("Gemini project is not configured").Err()
	}

	box := newSecretBox(s.cfg.SessionSecret)
	ctxDB, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	rec, err := getUserGeminiOAuth(ctxDB, s.db, box, username)
	if err != nil {
		log.Printf("ai gemini oauth get (%s): %v", username, err)
		return "", nil, errs.B().Code(errs.Unavailable).Msg("failed to load Gemini credentials").Err()
	}
	if rec == nil || strings.TrimSpace(rec.RefreshTokenEnc) == "" {
		return "", nil, errs.B().Code(errs.FailedPrecondition).Msg("Gemini is not connected").Err()
	}

	ts := cfg.TokenSource(ctx, &oauth2.Token{RefreshToken: strings.TrimSpace(rec.RefreshTokenEnc)})
	tok, err := ts.Token()
	if err != nil {
		log.Printf("ai gemini token refresh (%s): %v", username, err)
		return "", nil, errs.B().Code(errs.Unauthenticated).Msg("Gemini credentials expired; reconnect required").Err()
	}

	system := buildGeminiSystemPrompt(req.Kind, req.Constraints)
	userPrompt := buildGeminiUserPrompt(req.Kind, req.Prompt, req.SeedTemplate)

	body := geminiVertexGenerateRequest{
		Contents: []struct {
			Role  string `json:"role,omitempty"`
			Parts []struct {
				Text string `json:"text,omitempty"`
			} `json:"parts"`
		}{
			{
				Role: "user",
				Parts: []struct {
					Text string `json:"text,omitempty"`
				}{{Text: userPrompt}},
			},
		},
		SystemInstruction: &struct {
			Parts []struct {
				Text string `json:"text,omitempty"`
			} `json:"parts"`
		}{
			Parts: []struct {
				Text string `json:"text,omitempty"`
			}{{Text: system}},
		},
		GenerationConfig: map[string]any{},
	}
	if req.MaxOutputTokens > 0 {
		body.GenerationConfig["maxOutputTokens"] = req.MaxOutputTokens
	} else {
		body.GenerationConfig["maxOutputTokens"] = 2048
	}
	if req.Temperature > 0 {
		body.GenerationConfig["temperature"] = req.Temperature
	} else {
		body.GenerationConfig["temperature"] = 0.2
	}

	location := strings.TrimSpace(s.cfg.GeminiLocation)
	model := strings.TrimSpace(s.cfg.GeminiModel)
	project := strings.TrimSpace(s.cfg.GeminiProjectID)
	url := fmt.Sprintf("https://%s-aiplatform.googleapis.com/v1/projects/%s/locations/%s/publishers/google/models/%s:generateContent", location, project, location, model)

	b, _ := json.Marshal(body)
	httpReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	httpReq.Header.Set("Authorization", "Bearer "+strings.TrimSpace(tok.AccessToken))
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		log.Printf("ai gemini http (%s): %v", username, err)
		return "", nil, errs.B().Code(errs.Unavailable).Msg("failed to call Gemini").Err()
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if resp.StatusCode/100 != 2 {
		log.Printf("ai gemini http status (%s): %d %s", username, resp.StatusCode, string(respBody))
		return "", nil, errs.B().Code(errs.Unavailable).Msg("Gemini request failed").Err()
	}

	var out geminiVertexGenerateResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return "", nil, errs.B().Code(errs.Unavailable).Msg("failed to parse Gemini response").Err()
	}
	if len(out.Candidates) == 0 || len(out.Candidates[0].Content.Parts) == 0 {
		return "", nil, errs.B().Code(errs.Unavailable).Msg("Gemini returned empty output").Err()
	}

	text := strings.TrimSpace(out.Candidates[0].Content.Parts[0].Text)
	text = stripYAMLCodeFence(text)
	text = strings.TrimSpace(text)
	if text == "" {
		return "", nil, errs.B().Code(errs.Unavailable).Msg("Gemini returned empty output").Err()
	}
	if len(text) > 256*1024 {
		return "", nil, errs.B().Code(errs.InvalidArgument).Msg("Gemini output too large").Err()
	}
	if strings.Contains(text, "\u0000") {
		return "", nil, errs.B().Code(errs.InvalidArgument).Msg("invalid output").Err()
	}
	if countYAMLDocs(text) > 1 {
		return "", nil, errs.B().Code(errs.InvalidArgument).Msg("output must be a single YAML document").Err()
	}

	if err := validateYAML(text); err != nil {
		return "", nil, errs.B().Code(errs.InvalidArgument).Msg("generated output is not valid YAML").Err()
	}

	return text, nil, nil
}

func buildGeminiSystemPrompt(kind AITemplateKind, constraints []string) string {
	base := []string{
		"You are generating a single YAML file. Output YAML only; no markdown fences; no extra commentary.",
		"Do not reference external files, includes, or directories. Everything must be self-contained.",
		"Do not include secrets.",
	}
	switch kind {
	case AITemplateKindNetlab:
		base = append(base,
			"Target: netlab topology YAML. Provider must be clab (containerlab).",
			"Do not use libvirt.",
		)
	case AITemplateKindContainerlab:
		base = append(base, "Target: containerlab topology YAML.")
	}
	for _, c := range constraints {
		c = strings.TrimSpace(c)
		if c != "" {
			base = append(base, "Constraint: "+c)
		}
	}
	return strings.Join(base, "\n")
}

func buildGeminiUserPrompt(kind AITemplateKind, prompt string, seed string) string {
	var b strings.Builder
	b.WriteString("User request:\n")
	b.WriteString(strings.TrimSpace(prompt))
	b.WriteString("\n")
	if strings.TrimSpace(seed) != "" {
		b.WriteString("\nStarting template (use as a base and modify):\n")
		b.WriteString(strings.TrimSpace(seed))
		b.WriteString("\n")
	}
	return b.String()
}

func stripYAMLCodeFence(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "```") {
		// Remove first fence line.
		if idx := strings.Index(s, "\n"); idx >= 0 {
			s = s[idx+1:]
		} else {
			return ""
		}
		// Remove trailing fence.
		if idx := strings.LastIndex(s, "```"); idx >= 0 {
			s = s[:idx]
		}
	}
	return s
}

func countYAMLDocs(s string) int {
	// Heuristic: treat explicit document markers as multiple docs.
	// We intentionally keep this simple; validation will reject most junk anyway.
	docs := 1
	for _, line := range strings.Split(s, "\n") {
		if strings.TrimSpace(line) == "---" {
			docs++
		}
	}
	return docs
}

func validateYAML(s string) error {
	var m any
	if err := yaml.Unmarshal([]byte(s), &m); err != nil {
		return err
	}
	return nil
}
