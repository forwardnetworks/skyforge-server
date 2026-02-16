package skyforge

type netlabTaskSpec struct {
	Action          string            `json:"action,omitempty"`
	Server          string            `json:"server,omitempty"`
	Deployment      string            `json:"deployment,omitempty"`
	DeploymentID    string            `json:"deploymentId,omitempty"`
	UserRoot        string            `json:"userRoot,omitempty"`
	UserDir         string            `json:"userDir,omitempty"`
	TemplateSource  string            `json:"templateSource,omitempty"`
	TemplateRepo    string            `json:"templateRepo,omitempty"`
	TemplatesDir    string            `json:"templatesDir,omitempty"`
	Template        string            `json:"template,omitempty"`
	MultilabNumeric int               `json:"multilabNumeric,omitempty"`
	Cleanup         bool              `json:"cleanup,omitempty"`
	TopologyPath    string            `json:"topologyPath,omitempty"`
	ClabTarball     string            `json:"clabTarball,omitempty"`
	ClabConfigDir   string            `json:"clabConfigDir,omitempty"`
	ClabCleanup     bool              `json:"clabCleanup,omitempty"`
	Environment     map[string]string `json:"environment,omitempty"`
}

type netlabC9sTaskSpec struct {
	Action          string            `json:"action,omitempty"` // deploy|destroy
	Server          string            `json:"server,omitempty"`
	Deployment      string            `json:"deployment,omitempty"`
	DeploymentID    string            `json:"deploymentId,omitempty"`
	UserRoot        string            `json:"userRoot,omitempty"`
	UserDir         string            `json:"userDir,omitempty"`
	TemplateSource  string            `json:"templateSource,omitempty"`
	TemplateRepo    string            `json:"templateRepo,omitempty"`
	TemplatesDir    string            `json:"templatesDir,omitempty"`
	Template        string            `json:"template,omitempty"`
	MultilabNumeric int               `json:"multilabNumeric,omitempty"`
	TopologyPath    string            `json:"topologyPath,omitempty"`
	ClabTarball     string            `json:"clabTarball,omitempty"`
	K8sNamespace    string            `json:"k8sNamespace,omitempty"`
	LabName         string            `json:"labName,omitempty"`
	TopologyName    string            `json:"topologyName,omitempty"`
	Environment     map[string]string `json:"environment,omitempty"`
	SetOverrides    []string          `json:"setOverrides,omitempty"`
}
