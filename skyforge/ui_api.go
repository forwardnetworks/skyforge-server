package skyforge

import (
	"context"
)

type UIFeaturesResponse struct {
	GiteaEnabled         bool `json:"giteaEnabled"`
	ObjectStorageEnabled bool `json:"objectStorageEnabled"`
	DexEnabled           bool `json:"dexEnabled"`
	CoderEnabled         bool `json:"coderEnabled"`
	YaadeEnabled         bool `json:"yaadeEnabled"`
	SwaggerUIEnabled     bool `json:"swaggerUIEnabled"`
	ForwardEnabled       bool `json:"forwardEnabled"`
	NetboxEnabled        bool `json:"netboxEnabled"`
	NautobotEnabled      bool `json:"nautobotEnabled"`
	DNSEnabled           bool `json:"dnsEnabled"`
}

type UIConfigResponse struct {
	ProductName      string             `json:"productName"`
	ProductSubtitle  string             `json:"productSubtitle"`
	LogoURL          string             `json:"logoUrl"`
	LogoAlt          string             `json:"logoAlt"`
	HeaderBackground string             `json:"headerBackground"`
	SupportText      string             `json:"supportText"`
	SupportURL       string             `json:"supportUrl"`
	ThemeDefault     string             `json:"themeDefault"`
	ExternalURL      string             `json:"externalUrl"`
	OIDCEnabled      bool               `json:"oidcEnabled"`
	OIDCLoginURL     string             `json:"oidcLoginUrl"`
	Features         UIFeaturesResponse `json:"features"`
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
		Features: UIFeaturesResponse{
			GiteaEnabled:         s.cfg.Features.GiteaEnabled,
			ObjectStorageEnabled: s.cfg.Features.ObjectStorageEnabled,
			DexEnabled:           s.cfg.Features.DexEnabled,
			CoderEnabled:         s.cfg.Features.CoderEnabled,
			YaadeEnabled:         s.cfg.Features.YaadeEnabled,
			SwaggerUIEnabled:     s.cfg.Features.SwaggerUIEnabled,
			ForwardEnabled:       s.cfg.Features.ForwardEnabled,
			NetboxEnabled:        s.cfg.Features.NetboxEnabled,
			NautobotEnabled:      s.cfg.Features.NautobotEnabled,
			DNSEnabled:           s.cfg.Features.DNSEnabled,
		},
	}, nil
}
