package skyforge

import (
	"context"
	"strings"
	"time"

	"encore.app/internal/containerlabvalidate"
	"encore.dev/beta/errs"
)

// TemplateValidationKind is a legacy name used by existing UI flows. It no longer implies AI usage.
type TemplateValidationKind string

const (
	TemplateValidationKindNetlab       TemplateValidationKind = "netlab"
	TemplateValidationKindContainerlab TemplateValidationKind = "containerlab"
)

type UserAIValidateRequest struct {
	Kind         TemplateValidationKind `json:"kind"`
	Content      string                 `json:"content"`
	Environment  JSONMap                `json:"environment,omitempty"`
	SetOverrides []string               `json:"setOverrides,omitempty"`
}

type UserAIValidateResponse struct {
	WorkspaceID string  `json:"workspaceId"`
	Task        JSONMap `json:"task"`
}

// ValidateUserAITemplate validates a template.
//
// Despite the legacy path/name, this endpoint is deterministic and does not call any AI provider.
//
//encore:api auth method=POST path=/api/user/ai/validate
func (s *Service) ValidateUserAITemplate(ctx context.Context, req *UserAIValidateRequest) (*UserAIValidateResponse, error) {
	if _, err := requireAuthUser(); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("request required").Err()
	}
	kind := req.Kind
	content := strings.TrimSpace(req.Content)
	if content == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("content is required").Err()
	}
	if len(content) > 512*1024 {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("content too large").Err()
	}

	switch kind {
	case TemplateValidationKindContainerlab:
		errsList, err := containerlabvalidate.ValidateYAML(content)
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
		return &UserAIValidateResponse{WorkspaceID: "", Task: task}, nil
	case TemplateValidationKindNetlab:
		return nil, errs.B().Code(errs.Unimplemented).Msg("netlab validation is not supported via this endpoint").Err()
	default:
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid template kind").Err()
	}
}

type UserAIAutofixRequest struct {
	Kind          TemplateValidationKind `json:"kind"`
	Content       string                 `json:"content"`
	MaxIterations int                    `json:"maxIterations,omitempty"`
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

// AutofixUserAITemplate is a deterministic "autofix" helper for containerlab YAML.
//
// For now, it validates and returns the content unchanged. This keeps the UI wiring stable
// while avoiding any AI-provider dependency.
//
//encore:api auth method=POST path=/api/user/ai/autofix
func (s *Service) AutofixUserAITemplate(ctx context.Context, req *UserAIAutofixRequest) (*UserAIAutofixResponse, error) {
	if _, err := requireAuthUser(); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("request required").Err()
	}
	if req.Kind != TemplateValidationKindContainerlab {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("only containerlab autofix is supported").Err()
	}

	content := strings.TrimSpace(req.Content)
	if content == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("content is required").Err()
	}
	if len(content) > 512*1024 {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("content too large").Err()
	}

	errsList, err := containerlabvalidate.ValidateYAML(content)
	if err != nil {
		return nil, err
	}
	ok := len(errsList) == 0
	return &UserAIAutofixResponse{
		Kind:          "containerlab",
		Content:       content,
		Ok:            ok,
		Errors:        errsList,
		Iterations:    1,
		Warnings:      []string{},
		LastValidated: time.Now().UTC().Format(time.RFC3339Nano),
	}, nil
}
