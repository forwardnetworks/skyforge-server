package skyforge

import (
	"context"
	"strings"
)

type AdminEffectiveConfig struct {
	PublicURL string `json:"publicUrl"`

	Flags struct {
		TaskWorkerEnabled    bool `json:"taskWorkerEnabled"`
		NotificationsEnabled bool `json:"notificationsEnabled"`
		DisableEncoreCache   bool `json:"disableEncoreCache"`
	} `json:"flags"`

	NetlabGenerator struct {
		Mode          string `json:"mode"`
		GeneratorImage string `json:"generatorImage"`
		PullPolicy    string `json:"pullPolicy"`
	} `json:"netlabGenerator"`

	ObjectStorage struct {
		Endpoint string `json:"endpoint"`
		UseSSL   bool   `json:"useSsl"`
	} `json:"objectStorage"`

	Integrations struct {
		GiteaBaseURL    string `json:"giteaBaseUrl"`
		NetboxBaseURL   string `json:"netboxBaseUrl"`
		NautobotBaseURL string `json:"nautobotBaseUrl"`
		YaadeBaseURL    string `json:"yaadeBaseUrl"`
	} `json:"integrations"`

	ForwardCollector struct {
		Image                   string `json:"image"`
		PullPolicy              string `json:"pullPolicy"`
		ImagePullSecretName     string `json:"imagePullSecretName"`
		ImagePullSecretNamespace string `json:"imagePullSecretNamespace"`
		HeapSizeGB              int    `json:"heapSizeGb"`
	} `json:"forwardCollector"`

	Missing []string `json:"missing,omitempty"`
}

// GetAdminEffectiveConfig returns the effective (non-secret) typed Encore config (admin only).
//
// This endpoint is meant for self-diagnosis: it reports the config actually seen by the
// running API process (including defaults), plus a list of required fields that are missing.
//
//encore:api auth method=GET path=/api/admin/config tag:admin
func (s *Service) GetAdminEffectiveConfig(ctx context.Context) (*AdminEffectiveConfig, error) {
	if _, err := requireAdmin(); err != nil {
		return nil, err
	}

	out := &AdminEffectiveConfig{
		PublicURL: strings.TrimSpace(skyforgeEncoreCfg.PublicURL),
	}

	out.Flags.TaskWorkerEnabled = skyforgeEncoreCfg.TaskWorkerEnabled
	out.Flags.NotificationsEnabled = skyforgeEncoreCfg.NotificationsEnabled
	out.Flags.DisableEncoreCache = skyforgeEncoreCfg.DisableEncoreCache

	out.NetlabGenerator.Mode = strings.TrimSpace(skyforgeEncoreCfg.NetlabGenerator.C9sGeneratorMode)
	out.NetlabGenerator.GeneratorImage = strings.TrimSpace(skyforgeEncoreCfg.NetlabGenerator.GeneratorImage)
	out.NetlabGenerator.PullPolicy = strings.TrimSpace(skyforgeEncoreCfg.NetlabGenerator.PullPolicy)

	out.ObjectStorage.Endpoint = strings.TrimSpace(skyforgeEncoreCfg.ObjectStorage.Endpoint)
	out.ObjectStorage.UseSSL = skyforgeEncoreCfg.ObjectStorage.UseSSL

	out.Integrations.GiteaBaseURL = strings.TrimSpace(skyforgeEncoreCfg.Integrations.GiteaBaseURL)
	out.Integrations.NetboxBaseURL = strings.TrimSpace(skyforgeEncoreCfg.Integrations.NetboxBaseURL)
	out.Integrations.NautobotBaseURL = strings.TrimSpace(skyforgeEncoreCfg.Integrations.NautobotBaseURL)
	out.Integrations.YaadeBaseURL = strings.TrimSpace(skyforgeEncoreCfg.Integrations.YaadeBaseURL)

	out.ForwardCollector.Image = strings.TrimSpace(skyforgeEncoreCfg.ForwardCollector.Image)
	out.ForwardCollector.PullPolicy = strings.TrimSpace(skyforgeEncoreCfg.ForwardCollector.PullPolicy)
	out.ForwardCollector.ImagePullSecretName = strings.TrimSpace(skyforgeEncoreCfg.ForwardCollector.ImagePullSecretName)
	out.ForwardCollector.ImagePullSecretNamespace = strings.TrimSpace(skyforgeEncoreCfg.ForwardCollector.ImagePullSecretNamespace)
	out.ForwardCollector.HeapSizeGB = skyforgeEncoreCfg.ForwardCollector.HeapSizeGB

	// Required config (fail-safe self-diagnosis).
	if out.NetlabGenerator.Mode == "k8s" && out.NetlabGenerator.GeneratorImage == "" {
		out.Missing = append(out.Missing, "NetlabGenerator.GeneratorImage (skyforge.netlabC9s.generatorImage)")
	}
	if out.ObjectStorage.Endpoint == "" {
		out.Missing = append(out.Missing, "ObjectStorage.Endpoint (skyforge.objectStorage.endpoint)")
	}

	return out, nil
}
