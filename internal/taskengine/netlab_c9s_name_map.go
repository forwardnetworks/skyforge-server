package taskengine

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

func kubeUpsertC9sNameMapConfigMap(ctx context.Context, ns, topologyName string, sanitizedToOriginal map[string]string) error {
	ns = strings.TrimSpace(ns)
	topologyName = strings.TrimSpace(topologyName)
	if ns == "" || topologyName == "" || len(sanitizedToOriginal) == 0 {
		return nil
	}

	originalToSanitized := map[string]string{}
	outSanitizedToOriginal := map[string]string{}

	for sanitized, original := range sanitizedToOriginal {
		s := strings.TrimSpace(sanitized)
		o := strings.TrimSpace(original)
		if s == "" || o == "" {
			continue
		}
		outSanitizedToOriginal[s] = o
		originalToSanitized[o] = s
	}
	if len(originalToSanitized) == 0 || len(outSanitizedToOriginal) == 0 {
		return nil
	}

	payload := map[string]any{
		"originalToSanitized": originalToSanitized,
		"sanitizedToOriginal": outSanitizedToOriginal,
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encode c9s name mapping: %w", err)
	}

	cmName := sanitizeKubeNameFallback(fmt.Sprintf("c9s-%s-name-map", topologyName), "c9s-name-map")
	labels := map[string]string{
		"skyforge-c9s-topology": topologyName,
	}
	return kubeUpsertConfigMap(ctx, ns, cmName, map[string]string{
		"mapping.json": string(b),
	}, labels)
}
