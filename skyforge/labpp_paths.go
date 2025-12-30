package skyforge

import (
	"regexp"
	"strings"
)

var labppSafeFilename = regexp.MustCompile(`[^A-Za-z0-9]+`)

func labppLabFilename(template string) string {
	name := strings.TrimSpace(template)
	name = labppSafeFilename.ReplaceAllString(name, "_")
	name = strings.Trim(name, "_")
	if name == "" {
		name = "lab"
	}
	return name
}
