package skyforge

import (
	"context"

	"encore.app/internal/skyforgecore"
)

type UIConfigResponse struct {
	ProductName      string                      `json:"productName"`
	ProductSubtitle  string                      `json:"productSubtitle"`
	LogoURL          string                      `json:"logoUrl"`
	LogoAlt          string                      `json:"logoAlt"`
	HeaderBackground string                      `json:"headerBackground"`
	SupportText      string                      `json:"supportText"`
	SupportURL       string                      `json:"supportUrl"`
	ThemeDefault     string                      `json:"themeDefault"`
	ExternalURL      string                      `json:"externalUrl"`
	OIDCEnabled      bool                        `json:"oidcEnabled"`
	OIDCLoginURL     string                      `json:"oidcLoginUrl"`
	Features         skyforgecore.FeaturesConfig `json:"features"`
}

// GetUIConfig returns UI configuration values.
//
//encore:api public method=GET path=/api/ui/config
func (s *Service) GetUIConfig(ctx context.Context) (*UIConfigResponse, error) {
	return &UIConfigResponse{
		ProductName:      s.cfg.UI.ProductName,
		ProductSubtitle:  s.cfg.UI.ProductSubtitle,
		LogoURL:          s.cfg.UI.LogoURL,
		LogoAlt:          s.cfg.UI.LogoAlt,
		HeaderBackground: s.cfg.UI.HeaderBackground,
		SupportText:      s.cfg.UI.SupportText,
		SupportURL:       s.cfg.UI.SupportURL,
		ThemeDefault:     s.cfg.UI.ThemeDefault,
		ExternalURL:      detectCloudflaredQuickTunnelURL(ctx),
		OIDCEnabled:      s.cfg.UI.OIDCEnabled,
		OIDCLoginURL:     s.cfg.UI.OIDCLoginURL,
		Features:         s.cfg.Features,
	}, nil
}
