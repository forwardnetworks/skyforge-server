package taskengine

import (
	"fmt"
	"strings"
)

const kubeDefaultClusterDomain = "svc.cluster.local"

func kubeServiceFQDN(serviceName, namespace string) string {
	serviceName = strings.TrimSpace(serviceName)
	namespace = strings.TrimSpace(namespace)
	if serviceName == "" || namespace == "" {
		return ""
	}
	return fmt.Sprintf("%s.%s.%s", serviceName, namespace, kubeDefaultClusterDomain)
}
