package skyforge

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/oauth2"
	"gopkg.in/yaml.v3"

	"encore.app/internal/containerlabvalidate"
	"encore.dev/beta/errs"
)

type AITemplateProvider string

const (
	AITemplateProviderGemini AITemplateProvider = "gemini"
)

type AITemplateKind string

const (
	AITemplateKindNetlab       AITemplateKind = "netlab"
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

type UserAISaveRequest struct {
	Kind     AITemplateKind `json:"kind"`
	Content  string         `json:"content"`
	PathHint string         `json:"pathHint,omitempty"`
	// Filename is an optional user-provided base filename (repo-relative name is computed
	// from Kind + PathHint). If provided, it may include the expected extension.
	// Examples:
	// - netlab: "bgp-demo" or "bgp-demo.yml"
	// - containerlab: "dc1" or "dc1.clab.yml"
	Filename string `json:"filename,omitempty"`
	Message  string         `json:"message,omitempty"`
}

type UserAISaveResponse struct {
	WorkspaceID string `json:"workspaceId"`
	Repo        string `json:"repo"`
	Branch      string `json:"branch"`
	Path        string `json:"path"`
}

type UserAIValidateRequest struct {
	Kind         AITemplateKind `json:"kind"`
	Content      string         `json:"content"`
	Environment  JSONMap        `json:"environment,omitempty"`
	SetOverrides []string       `json:"setOverrides,omitempty"`
}

type UserAIValidateResponse struct {
	WorkspaceID string  `json:"workspaceId"`
	Task        JSONMap `json:"task"`
}

type UserAIAutofixRequest struct {
	Kind          AITemplateKind `json:"kind"`
	Content       string         `json:"content"`
	MaxIterations int            `json:"maxIterations,omitempty"`
}

type UserAIAutofixResponse struct {
	Kind          string   `json:"kind"`
	Content       string   `json:"content"`
	Ok            bool     `json:"ok"`
	Errors        []string `json:"errors,omitempty"`
	Iterations    int      `json:"iterations"`
	Warnings      []string `json:"warnings,omitempty"`
	LastValidated string   `json:"lastValidated"`
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

// AutofixUserAITemplate runs a short validate→regenerate loop for containerlab templates.
//
// This is intentionally synchronous and bounded so it can be used from the UI without spawning jobs.
//
//encore:api auth method=POST path=/api/user/ai/autofix
func (s *Service) AutofixUserAITemplate(ctx context.Context, req *UserAIAutofixRequest) (*UserAIAutofixResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if !s.cfg.AIEnabled {
		return nil, errs.B().Code(errs.NotFound).Msg("AI is disabled").Err()
	}
	if !s.cfg.GeminiEnabled {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg("Gemini is disabled").Err()
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	if req == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("request required").Err()
	}
	if req.Kind != AITemplateKindContainerlab {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg("only containerlab autofix is supported right now").Err()
	}

	content := strings.TrimSpace(req.Content)
	if content == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("content is required").Err()
	}
	if len(content) > 256*1024 {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("content too large").Err()
	}
	if strings.Contains(content, "\u0000") {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid content").Err()
	}
	if countYAMLDocs(content) > 1 {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("content must be a single YAML document").Err()
	}
	if err := validateYAML(content); err != nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("content is not valid YAML").Err()
	}

	username := strings.ToLower(strings.TrimSpace(user.Username))

	errsList, err := containerlabvalidate.ValidateYAML(content)
	if err != nil {
		return nil, err
	}
	if len(errsList) == 0 {
		return &UserAIAutofixResponse{
			Kind:          string(req.Kind),
			Content:       content,
			Ok:            true,
			Errors:        []string{},
			Iterations:    0,
			Warnings:      []string{},
			LastValidated: time.Now().UTC().Format(time.RFC3339Nano),
		}, nil
	}

	maxIters := req.MaxIterations
	if maxIters <= 0 {
		maxIters = 3
	}
	if maxIters > 5 {
		maxIters = 5
	}

	var allWarnings []string
	for i := 0; i < maxIters; i++ {
		trimmedErrs := trimSchemaErrors(errsList, 25, 220)
		fixPrompt := "Fix the containerlab topology so it passes JSON schema validation. " +
			"Preserve node names and overall intent. Do not remove required sections. " +
			"Do not add external file references.\n\n" +
			"Schema errors:\n- " + strings.Join(trimmedErrs, "\n- ")

		genReq := &UserAIGenerateRequest{
			Provider:     AITemplateProviderGemini,
			Kind:         AITemplateKindContainerlab,
			Prompt:       fixPrompt,
			SeedTemplate: content,
			Constraints: []string{
				"containerlab",
				"must pass JSON schema validation",
				"single file",
			},
			MaxOutputTokens: 2048,
			Temperature:     0.2,
		}

		next, warnings, err := s.generateWithGeminiVertex(ctx, username, genReq)
		if err != nil {
			return nil, err
		}
		if len(warnings) > 0 {
			allWarnings = append(allWarnings, warnings...)
		}

		nextErrs, err := containerlabvalidate.ValidateYAML(next)
		if err != nil {
			return nil, err
		}
		content = next
		errsList = nextErrs
		if len(errsList) == 0 {
			return &UserAIAutofixResponse{
				Kind:          string(req.Kind),
				Content:       content,
				Ok:            true,
				Errors:        []string{},
				Iterations:    i + 1,
				Warnings:      allWarnings,
				LastValidated: time.Now().UTC().Format(time.RFC3339Nano),
			}, nil
		}
	}

	return &UserAIAutofixResponse{
		Kind:          string(req.Kind),
		Content:       content,
		Ok:            false,
		Errors:        trimSchemaErrors(errsList, 50, 400),
		Iterations:    maxIters,
		Warnings:      allWarnings,
		LastValidated: time.Now().UTC().Format(time.RFC3339Nano),
	}, nil
}

// SaveUserAITemplate writes generated template content into the user's default workspace repo.
//
//encore:api auth method=POST path=/api/user/ai/save
func (s *Service) SaveUserAITemplate(ctx context.Context, req *UserAISaveRequest) (*UserAISaveResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	if req == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("request required").Err()
	}
	if req.Kind != AITemplateKindNetlab && req.Kind != AITemplateKindContainerlab {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid template kind").Err()
	}
	content := strings.TrimSpace(req.Content)
	if content == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("content is required").Err()
	}
	if len(content) > 256*1024 {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("content too large").Err()
	}
	if strings.Contains(content, "\u0000") {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid content").Err()
	}
	if countYAMLDocs(content) > 1 {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("content must be a single YAML document").Err()
	}
	if err := validateYAML(content); err != nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("content is not valid YAML").Err()
	}

	ws, err := s.ensureDefaultWorkspace(ctx, user)
	if err != nil {
		return nil, err
	}
	if ws == nil || strings.TrimSpace(ws.ID) == "" {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to resolve workspace").Err()
	}
	if strings.TrimSpace(s.cfg.Workspaces.GiteaAPIURL) == "" ||
		strings.TrimSpace(ws.GiteaOwner) == "" ||
		strings.TrimSpace(ws.GiteaRepo) == "" {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg("Gitea is not configured for this workspace").Err()
	}

	// Ensure repo exists and is set to correct visibility.
	if strings.TrimSpace(s.cfg.Workspaces.GiteaAPIURL) != "" && strings.TrimSpace(s.cfg.Workspaces.GiteaUsername) != "" {
		_ = ensureGiteaRepoFromBlueprint(s.cfg, ws.GiteaOwner, ws.GiteaRepo, ws.Blueprint, s.cfg.Workspaces.GiteaRepoPrivate)
	}

	branch := strings.TrimSpace(ws.DefaultBranch)
	if branch == "" {
		branch = "main"
	}

	pathHint := strings.Trim(strings.TrimSpace(req.PathHint), "/")
	if pathHint == "" {
		pathHint = "ai"
	}
	if !isSafeRelativePath(pathHint) {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("pathHint must be a safe repo-relative path").Err()
	}

	ext := ".yml"
	dir := "blueprints/netlab/" + pathHint
	if req.Kind == AITemplateKindContainerlab {
		ext = ".clab.yml"
		dir = "blueprints/containerlab/" + pathHint
	}

	slug := uuid.New().String()
	if strings.TrimSpace(req.Filename) != "" {
		base, err := sanitizeTemplateBasename(req.Filename, ext)
		if err != nil {
			return nil, errs.B().Code(errs.InvalidArgument).Msg(err.Error()).Err()
		}
		slug = base
	}
	filePath := path.Join(dir, slug+ext)
	if !isSafeRelativePath(filePath) {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("generated path is not safe").Err()
	}

	msg := "ai: add " + string(req.Kind) + " template"
	if strings.TrimSpace(req.Message) != "" {
		msg = msg + " (" + strings.TrimSpace(req.Message) + ")"
	}

	claims := claimsFromAuthUser(user)
	if err := ensureGiteaFile(s.cfg, ws.GiteaOwner, ws.GiteaRepo, filePath, content, msg, branch, claims); err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to save template").Err()
	}

	return &UserAISaveResponse{
		WorkspaceID: ws.ID,
		Repo:        fmt.Sprintf("%s/%s", ws.GiteaOwner, ws.GiteaRepo),
		Branch:      branch,
		Path:        filePath,
	}, nil
}

func sanitizeTemplateBasename(filename string, requiredExt string) (string, error) {
	name := strings.TrimSpace(filename)
	if name == "" {
		return "", fmt.Errorf("filename is empty")
	}
	name = strings.Trim(name, "/")
	if strings.Contains(name, "/") || strings.Contains(name, "\\") {
		return "", fmt.Errorf("filename must not contain path separators")
	}

	// Allow the user to include the expected extension.
	switch {
	case strings.HasSuffix(name, requiredExt):
		name = strings.TrimSuffix(name, requiredExt)
	case strings.Contains(name, "."):
		// Reject other extensions to keep naming predictable and avoid confusing dropdowns.
		return "", fmt.Errorf("filename must end with %s", requiredExt)
	}

	name = strings.Trim(name, ".-_")
	if name == "" {
		return "", fmt.Errorf("filename is invalid")
	}
	if len(name) > 120 {
		return "", fmt.Errorf("filename too long")
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-' || r == '_' || r == '.':
		default:
			return "", fmt.Errorf("filename contains invalid characters")
		}
	}
	return name, nil
}

// ValidateUserAITemplate persists a generated netlab template and enqueues a netlab validation task.
//
//encore:api auth method=POST path=/api/user/ai/validate
func (s *Service) ValidateUserAITemplate(ctx context.Context, req *UserAIValidateRequest) (*UserAIValidateResponse, error) {
	if _, err := requireAuthUser(); err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	if req == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("request required").Err()
	}
	if req.Kind != AITemplateKindNetlab && req.Kind != AITemplateKindContainerlab {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid template kind").Err()
	}

	if req.Kind == AITemplateKindContainerlab {
		errsList, err := containerlabvalidate.ValidateYAML(req.Content)
		if err != nil {
			return nil, err
		}
		task, err := toJSONMap(map[string]any{
			"kind":   "containerlab",
			"ok":     len(errsList) == 0,
			"errors": errsList,
		})
		if err != nil {
			return nil, errs.B().Code(errs.Unavailable).Msg("failed to encode validation result").Err()
		}
		return &UserAIValidateResponse{
			WorkspaceID: "",
			Task:        task,
		}, nil
	}

	// Save into a deterministic validate folder so we can call the existing validate API by filename.
	saveResp, err := s.SaveUserAITemplate(ctx, &UserAISaveRequest{
		Kind:     req.Kind,
		Content:  req.Content,
		PathHint: "ai/validate",
		Message:  "validate",
	})
	if err != nil {
		return nil, err
	}

	wsID := strings.TrimSpace(saveResp.WorkspaceID)
	if wsID == "" {
		return nil, errs.B().Code(errs.Unavailable).Msg("workspace unavailable").Err()
	}

	templateDir := path.Dir(saveResp.Path)
	templateFile := path.Base(saveResp.Path)

	run, err := s.ValidateWorkspaceNetlabTemplate(ctx, wsID, &WorkspaceNetlabValidateRequest{
		Source:       "workspace",
		Dir:          templateDir,
		Template:     templateFile,
		Environment:  req.Environment,
		SetOverrides: req.SetOverrides,
	})
	if err != nil {
		return nil, err
	}
	if run == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to start validation").Err()
	}

	return &UserAIValidateResponse{
		WorkspaceID: wsID,
		Task:        run.Task,
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

func geminiVertexEndpointURL(project, location, model string) string {
	location = strings.TrimSpace(location)
	model = strings.TrimSpace(model)
	project = strings.TrimSpace(project)

	base := ""
	if location == "" || strings.EqualFold(location, "global") {
		base = "https://aiplatform.googleapis.com"
		location = "global"
	} else {
		base = fmt.Sprintf("https://%s-aiplatform.googleapis.com", location)
	}

	return fmt.Sprintf(
		"%s/v1/projects/%s/locations/%s/publishers/google/models/%s:generateContent",
		base,
		project,
		location,
		model,
	)
}

type geminiVertexAttempt struct {
	Location string
	Model    string
}

func geminiModelAliases(model string) []string {
	model = strings.TrimSpace(model)
	if model == "" {
		return nil
	}
	out := []string{model}
	// Accept common "3.0" aliases (some docs/UI surfaces include the ".0", while
	// the Vertex publisher model IDs may omit it).
	if strings.Contains(model, "gemini-3.0-") {
		out = append(out, strings.Replace(model, "gemini-3.0-", "gemini-3-", 1))
	}
	// Deduplicate.
	seen := map[string]struct{}{}
	uniq := make([]string, 0, len(out))
	for _, m := range out {
		m = strings.TrimSpace(m)
		if m == "" {
			continue
		}
		if _, ok := seen[m]; ok {
			continue
		}
		seen[m] = struct{}{}
		uniq = append(uniq, m)
	}
	return uniq
}

func isGeminiModelNotAvailableError(body string) bool {
	lower := strings.ToLower(strings.TrimSpace(body))
	if lower == "" {
		return false
	}
	if !strings.Contains(lower, "model") && !strings.Contains(lower, "models") {
		return false
	}
	return strings.Contains(lower, "not found") ||
		strings.Contains(lower, "not available") ||
		strings.Contains(lower, "could not find") ||
		strings.Contains(lower, "invalid model") ||
		strings.Contains(lower, "model is not supported")
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
	fallbackModel := strings.TrimSpace(s.cfg.GeminiFallbackModel)
	project := strings.TrimSpace(s.cfg.GeminiProjectID)

	b, _ := json.Marshal(body)
	doRequest := func(location, model string) (*http.Response, []byte, error) {
		endpointURL := geminiVertexEndpointURL(project, location, model)
		httpReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, endpointURL, bytes.NewReader(b))
		httpReq.Header.Set("Authorization", "Bearer "+strings.TrimSpace(tok.AccessToken))
		httpReq.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(httpReq)
		if err != nil {
			return nil, nil, err
		}
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
		_ = resp.Body.Close()
		return resp, respBody, nil
	}

	// Try primary model first, then fallback if configured. For each model, try
	// the configured location first and retry once against the global endpoint if
	// we get a "model not available" style error.
	//
	// This avoids a common pitfall where users can access a model in Vertex AI
	// Studio but the regional API endpoint returns an availability error, and it
	// also lets us gracefully fall back from a "pro" model to a "flash" model.
	modelCandidates := []string{}
	modelCandidates = append(modelCandidates, geminiModelAliases(model)...)
	if fallbackModel != "" && fallbackModel != model {
		modelCandidates = append(modelCandidates, geminiModelAliases(fallbackModel)...)
	}
	// Final dedupe (across primary+fallback+aliases).
	seenModels := map[string]struct{}{}
	uniqModels := make([]string, 0, len(modelCandidates))
	for _, m := range modelCandidates {
		m = strings.TrimSpace(m)
		if m == "" {
			continue
		}
		if _, ok := seenModels[m]; ok {
			continue
		}
		seenModels[m] = struct{}{}
		uniqModels = append(uniqModels, m)
	}

	attempts := []geminiVertexAttempt{}
	for _, m := range uniqModels {
		attempts = append(attempts, geminiVertexAttempt{Location: location, Model: m})
		if !strings.EqualFold(location, "global") {
			attempts = append(attempts, geminiVertexAttempt{Location: "global", Model: m})
		}
	}

	var resp *http.Response
	var respBody []byte
	for _, a := range attempts {
		resp, respBody, err = doRequest(a.Location, a.Model)
		if err != nil {
			log.Printf("ai gemini http (%s): %v", username, err)
			return "", nil, errs.B().Code(errs.Unavailable).Msg("failed to call Gemini").Err()
		}
		if resp.StatusCode/100 == 2 {
			break
		}
		bodyStr := strings.TrimSpace(string(respBody))
		if (resp.StatusCode == 400 || resp.StatusCode == 404) && isGeminiModelNotAvailableError(bodyStr) {
			// Try next attempt.
			continue
		}
		// Non-availability errors are handled below with the latest response.
		break
	}

	if resp.StatusCode/100 != 2 {
		bodyStr := strings.TrimSpace(string(respBody))
		log.Printf("ai gemini http status (%s): %d %s", username, resp.StatusCode, bodyStr)

		enableURL := fmt.Sprintf("https://console.cloud.google.com/apis/library/aiplatform.googleapis.com?project=%s", url.QueryEscape(project))

		// Try to surface actionable errors (common onboarding issues: API disabled, IAM missing, model not found).
		lower := strings.ToLower(bodyStr)
		switch resp.StatusCode {
		case 400:
			if isGeminiModelNotAvailableError(bodyStr) {
				msg := "Gemini model not available; verify the configured model name(s) and that they are enabled for the configured project/location"
				if fallbackModel != "" && fallbackModel != model {
					msg = msg + fmt.Sprintf(" (tried %q then %q)", model, fallbackModel)
				} else if model != "" {
					msg = msg + fmt.Sprintf(" (tried %q)", model)
				}
				return "", nil, errs.B().Code(errs.FailedPrecondition).Msg(msg).Err()
			}
			return "", nil, errs.B().Code(errs.InvalidArgument).Msg("Gemini request rejected; check prompt/constraints and try again").Err()
		case 401:
			return "", nil, errs.B().Code(errs.Unauthenticated).Msg("Gemini credentials expired; reconnect required").Err()
		case 403:
			// If the API is disabled in the shared project, Google typically returns a PERMISSION_DENIED error that
			// mentions the API not being used/enabled. This is confusing to end users; provide a direct enable link.
			if strings.Contains(lower, "has not been used in project") ||
				strings.Contains(lower, "service disabled") ||
				strings.Contains(lower, "aiplatform.googleapis.com") {
				return "", nil, errs.B().Code(errs.FailedPrecondition).Msg("Vertex AI API is disabled for the configured project; ask an admin to enable it: " + enableURL).Err()
			}
			return "", nil, errs.B().Code(errs.PermissionDenied).Msg("Missing permission to use Vertex AI in the configured project; ask an admin to grant Vertex AI User access").Err()
		case 404:
			// Model not found or API not enabled can surface as 404 depending on org setup.
			if isGeminiModelNotAvailableError(bodyStr) || strings.Contains(lower, "not found") || strings.Contains(lower, "models") {
				return "", nil, errs.B().Code(errs.FailedPrecondition).Msg("Gemini model not available; verify the configured model name and that Vertex AI is enabled for the project").Err()
			}
			return "", nil, errs.B().Code(errs.FailedPrecondition).Msg("Vertex AI endpoint not found; verify project/location/model and that the API is enabled: " + enableURL).Err()
		default:
			// Preserve the raw response for debugging, but keep it concise.
			msg := "Gemini request failed"
			if bodyStr != "" {
				const max = 400
				if len(bodyStr) > max {
					bodyStr = bodyStr[:max] + "…"
				}
				msg = msg + ": " + bodyStr
			}
			return "", nil, errs.B().Code(errs.Unavailable).Msg(msg).Err()
		}
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
		raw := text
		truncated := false
		const maxRaw = 16 * 1024
		if len(raw) > maxRaw {
			raw = raw[:maxRaw]
			truncated = true
		}
		builder := errs.B().Code(errs.InvalidArgument).Msg("generated output is not valid YAML").Meta("rawOutput", raw)
		if truncated {
			builder = builder.Meta("rawOutputTruncated", true)
		}
		return "", nil, builder.Err()
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

func trimSchemaErrors(errsIn []string, max int, maxLen int) []string {
	if max <= 0 {
		max = 25
	}
	if maxLen <= 0 {
		maxLen = 300
	}
	out := make([]string, 0, len(errsIn))
	for _, e := range errsIn {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if len(e) > maxLen {
			e = e[:maxLen] + "…"
		}
		out = append(out, e)
		if len(out) >= max {
			break
		}
	}
	if len(out) == 0 {
		return []string{"schema validation failed"}
	}
	return out
}
