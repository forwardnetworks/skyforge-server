package skyforge

import "encoding/json"

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
