package containerlabvalidate

import (
	"embed"
	"encoding/json"
	"regexp"
	"strings"
	"sync"

	"github.com/xeipuuv/gojsonschema"
	"gopkg.in/yaml.v3"

	"encore.dev/beta/errs"
)

//go:embed clab.schema.json
var clabSchemaFS embed.FS

var (
	clabSchemaOnce sync.Once
	clabSchema     *gojsonschema.Schema
	clabSchemaErr  error
)

func getSchema() (*gojsonschema.Schema, error) {
	clabSchemaOnce.Do(func() {
		b, err := clabSchemaFS.ReadFile("clab.schema.json")
		if err != nil {
			clabSchemaErr = err
			return
		}
		loader := gojsonschema.NewBytesLoader(b)
		clabSchema, clabSchemaErr = gojsonschema.NewSchema(loader)
	})
	if clabSchemaErr != nil {
		return nil, clabSchemaErr
	}
	return clabSchema, nil
}

var envDefaultRe = regexp.MustCompile(`^\$\{[A-Za-z_][A-Za-z0-9_]*(:=|:-)(.*)\}$`)

func normalizeEnvDefaults(v any) any {
	switch t := v.(type) {
	case string:
		s := strings.TrimSpace(t)
		m := envDefaultRe.FindStringSubmatch(s)
		if len(m) == 3 {
			def := strings.TrimSpace(m[2])
			def = strings.TrimSuffix(strings.TrimPrefix(def, `"`), `"`)
			def = strings.TrimSuffix(strings.TrimPrefix(def, `'`), `'`)
			return def
		}
		return t
	case []any:
		out := make([]any, 0, len(t))
		for _, it := range t {
			out = append(out, normalizeEnvDefaults(it))
		}
		return out
	case map[string]any:
		out := map[string]any{}
		for k, v2 := range t {
			out[k] = normalizeEnvDefaults(v2)
		}
		return out
	case map[any]any:
		out := map[any]any{}
		for k, v2 := range t {
			out[k] = normalizeEnvDefaults(v2)
		}
		return out
	default:
		return v
	}
}

func yamlToJSONValue(v any) (any, error) {
	switch t := v.(type) {
	case nil:
		return nil, nil
	case bool, float64, int, int64, uint64, string:
		return t, nil
	case []any:
		out := make([]any, 0, len(t))
		for _, it := range t {
			jv, err := yamlToJSONValue(it)
			if err != nil {
				return nil, err
			}
			out = append(out, jv)
		}
		return out, nil
	case map[string]any:
		out := map[string]any{}
		for k, v2 := range t {
			jv, err := yamlToJSONValue(v2)
			if err != nil {
				return nil, err
			}
			out[k] = jv
		}
		return out, nil
	case map[any]any:
		out := map[string]any{}
		for k, v2 := range t {
			ks, ok := k.(string)
			if !ok {
				return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid YAML: non-string map key").Err()
			}
			jv, err := yamlToJSONValue(v2)
			if err != nil {
				return nil, err
			}
			out[ks] = jv
		}
		return out, nil
	default:
		// yaml.v3 can produce map[interface{}]interface{} nested forms; normalize through JSON.
		b, err := json.Marshal(t)
		if err != nil {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid YAML value").Err()
		}
		var out any
		if err := json.Unmarshal(b, &out); err != nil {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid YAML value").Err()
		}
		return out, nil
	}
}

// ValidateYAML validates a containerlab topology YAML against the official containerlab JSON schema.
//
// It returns a list of human-readable schema errors (empty when valid).
func ValidateYAML(yamlContent string) ([]string, error) {
	content := strings.TrimSpace(yamlContent)
	if content == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("content is required").Err()
	}

	schema, err := getSchema()
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("containerlab schema unavailable").Err()
	}

	var doc any
	if err := yaml.Unmarshal([]byte(content), &doc); err != nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid YAML").Err()
	}

	doc = normalizeEnvDefaults(doc)

	jv, err := yamlToJSONValue(doc)
	if err != nil {
		return nil, err
	}

	res, err := schema.Validate(gojsonschema.NewGoLoader(jv))
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("schema validation failed").Err()
	}
	if res.Valid() {
		return []string{}, nil
	}

	out := make([]string, 0, len(res.Errors()))
	for _, e := range res.Errors() {
		out = append(out, e.String())
	}
	return out, nil
}
