package skyforge

type PolicyReportForwardCredentialsStatus struct {
	Configured    bool   `json:"configured"`
	BaseURL       string `json:"baseUrl,omitempty"`
	SkipTLSVerify bool   `json:"skipTlsVerify"`
	Username      string `json:"username,omitempty"`
	HasPassword   bool   `json:"hasPassword"`
	UpdatedAt     string `json:"updatedAt,omitempty"`
}

type PolicyReportPutForwardCredentialsRequest struct {
	BaseURL       string `json:"baseUrl"`
	SkipTLSVerify bool   `json:"skipTlsVerify"`
	Username      string `json:"username"`
	Password      string `json:"password,omitempty"`
}
