package skyforge

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

type JSONMap map[string]json.RawMessage

func toJSONMap(value map[string]any) (JSONMap, error) {
	if value == nil {
		return nil, nil
	}
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var out map[string]json.RawMessage
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return JSONMap(out), nil
}

func toJSONMapSlice(values []map[string]any) ([]JSONMap, error) {
	if values == nil {
		return nil, nil
	}
	out := make([]JSONMap, 0, len(values))
	for _, value := range values {
		converted, err := toJSONMap(value)
		if err != nil {
			return nil, err
		}
		out = append(out, converted)
	}
	return out, nil
}

func fromJSONMap(value JSONMap) (map[string]any, error) {
	if value == nil {
		return nil, nil
	}
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func getJSONMapString(value JSONMap, key string) string {
	if value == nil {
		return ""
	}
	raw, ok := value[key]
	if !ok {
		return ""
	}
	var out string
	if err := json.Unmarshal(raw, &out); err == nil {
		return strings.TrimSpace(out)
	}
	var anyVal any
	if err := json.Unmarshal(raw, &anyVal); err == nil {
		return strings.TrimSpace(fmt.Sprintf("%v", anyVal))
	}
	return ""
}

func getJSONMapInt(value JSONMap, key string) int {
	if value == nil {
		return 0
	}
	raw, ok := value[key]
	if !ok {
		return 0
	}
	var out int
	if err := json.Unmarshal(raw, &out); err == nil {
		return out
	}
	var out64 int64
	if err := json.Unmarshal(raw, &out64); err == nil {
		return int(out64)
	}
	var f float64
	if err := json.Unmarshal(raw, &f); err == nil {
		return int(f)
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		if parsed, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
			return parsed
		}
	}
	return 0
}
