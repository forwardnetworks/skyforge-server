package skyforge

import (
	"encore.app/internal/jsonmap"
)

type JSONMap = jsonmap.JSONMap

func toJSONMap(value map[string]any) (JSONMap, error) {
	return jsonmap.ToJSONMap(value)
}

func toJSONMapSlice(values []map[string]any) ([]JSONMap, error) {
	return jsonmap.ToJSONMapSlice(values)
}

func fromJSONMap(value JSONMap) (map[string]any, error) {
	return jsonmap.FromJSONMap(value)
}

func getJSONMapString(value JSONMap, key string) string {
	return jsonmap.GetString(value, key)
}

func getJSONMapInt(value JSONMap, key string) int {
	return jsonmap.GetInt(value, key)
}
