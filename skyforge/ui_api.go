package skyforge

import "context"

type UIConfigResponse struct {
	ProductName      string `json:"productName"`
	ProductSubtitle  string `json:"productSubtitle"`
	LogoURL          string `json:"logoUrl"`
	LogoAlt          string `json:"logoAlt"`
	HeaderBackground string `json:"headerBackground"`
	SupportText      string `json:"supportText"`
	SupportURL       string `json:"supportUrl"`
	ThemeDefault     string `json:"themeDefault"`
}

// GetUIConfig returns UI configuration values.
//
//encore:api public method=GET path=/api/ui/config
func (s *Service) GetUIConfig(_ context.Context) (*UIConfigResponse, error) {
	return &UIConfigResponse{
		ProductName:      s.cfg.UI.ProductName,
		ProductSubtitle:  s.cfg.UI.ProductSubtitle,
		LogoURL:          s.cfg.UI.LogoURL,
		LogoAlt:          s.cfg.UI.LogoAlt,
		HeaderBackground: s.cfg.UI.HeaderBackground,
		SupportText:      s.cfg.UI.SupportText,
		SupportURL:       s.cfg.UI.SupportURL,
		ThemeDefault:     s.cfg.UI.ThemeDefault,
	}, nil
}

// GetUIConfigV1 returns UI configuration values (v1 alias).
//
//encore:api public method=GET path=/api/v1/ui/config
func (s *Service) GetUIConfigV1(ctx context.Context) (*UIConfigResponse, error) {
	return s.GetUIConfig(ctx)
}
