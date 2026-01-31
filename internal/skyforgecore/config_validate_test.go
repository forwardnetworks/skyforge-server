package skyforgecore

import "testing"

func TestValidateConfig(t *testing.T) {
	cfg := Config{
		NetlabC9sGeneratorMode: "k8s",
		NetlabGeneratorImage:   "",
		Features: FeaturesConfig{
			DexEnabled:     true,
			DNSEnabled:     true,
			ForwardEnabled: true,
		},
		UI:     UIConfig{OIDCEnabled: false},
		DNSURL: "",
	}
	got := ValidateConfig(cfg)
	if len(got.Errors) == 0 {
		t.Fatalf("expected errors, got none")
	}
}
