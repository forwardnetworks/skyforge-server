package skyforge

import (
	"path"
	"regexp"
	"strings"
	"time"
)

var labppSafeFilename = regexp.MustCompile(`[^A-Za-z0-9]+`)

func labppLabFilename(template string) string {
	return labppSafeSegment(template, "lab")
}

func labppSafeSegment(value, fallback string) string {
	name := strings.TrimSpace(value)
	name = labppSafeFilename.ReplaceAllString(name, "_")
	name = strings.Trim(name, "_")
	if name == "" {
		name = fallback
	}
	return name
}

func labppLabPath(username, deployment, template string, now time.Time) string {
	stamp := now.UTC().Format("20060102-1504")
	segments := []string{
		labppSafeSegment(username, ""),
		labppSafeSegment(deployment, ""),
		labppLabFilename(template),
		stamp,
	}
	parts := make([]string, 0, len(segments))
	for _, seg := range segments {
		if seg != "" {
			parts = append(parts, seg)
		}
	}
	base := strings.Join(parts, "_")
	if base == "" {
		base = "lab_" + stamp
	}
	return "/" + base
}

func labppNormalizeFolderPath(folder string) string {
	clean := strings.TrimSpace(folder)
	if clean == "" {
		return ""
	}
	clean = strings.TrimPrefix(clean, "/")
	clean = strings.TrimSuffix(clean, "/")
	if strings.HasSuffix(clean, ".unl") {
		clean = path.Dir(clean)
	}
	if clean == "." {
		return ""
	}
	return "/" + clean
}

func labppLabFilePath(folder, template string) string {
	trimmed := strings.Trim(labppNormalizeFolderPath(folder), "/")
	if trimmed == "" {
		return "/" + labppLabFilename(template) + ".unl"
	}
	return "/" + trimmed + "/" + labppLabFilename(template) + ".unl"
}
