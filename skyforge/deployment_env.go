package skyforge

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"maps"
	"regexp"
	"strconv"
	"strings"
	"time"

	"encore.dev/beta/errs"
)

var envKeyPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func (s *Service) mergeDeploymentEnvironment(ctx context.Context, userScopeID, username string, cfgAny map[string]any) (map[string]string, error) {
	if s.db == nil {
		return map[string]string{}, nil
	}
	groupIDs := parseEnvGroupIDs(cfgAny["envGroupIds"])
	scope := parseEnvGroupScope(cfgAny["envGroupScope"])
	groupEnv := map[string]string{}
	if len(groupIDs) > 0 {
		var err error
		if scope == "user" {
			groupEnv, err = loadUserVariableGroupsByID(ctx, s.db, username, groupIDs)
		} else {
			groupEnv, err = loadUserScopeVariableGroupsByID(ctx, s.db, userScopeID, groupIDs)
		}
		if err != nil {
			return nil, err
		}
	}

	env := map[string]string{}
	maps.Copy(env, groupEnv)
	maps.Copy(env, parseEnvMap(cfgAny["environment"]))
	for k, v := range parseEnvMap(cfgAny["env"]) {
		if _, exists := env[k]; exists {
			continue
		}
		env[k] = v
	}
	return env, nil
}

func parseEnvGroupScope(raw any) string {
	if v, ok := raw.(string); ok {
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "user":
			return "user"
		}
	}
	return "user"
}

func parseEnvGroupIDs(raw any) []int {
	switch v := raw.(type) {
	case []any:
		out := make([]int, 0, len(v))
		for _, item := range v {
			if id, ok := parseEnvGroupID(item); ok {
				out = append(out, id)
			}
		}
		return out
	case []int:
		return append([]int(nil), v...)
	default:
		if id, ok := parseEnvGroupID(raw); ok {
			return []int{id}
		}
	}
	return nil
}

func parseEnvGroupID(raw any) (int, bool) {
	switch v := raw.(type) {
	case int:
		return v, true
	case int64:
		return int(v), true
	case float64:
		return int(v), true
	case string:
		v = strings.TrimSpace(v)
		if v == "" {
			return 0, false
		}
		if parsed, err := strconv.Atoi(v); err == nil {
			return parsed, true
		}
	}
	return 0, false
}

func parseEnvMap(raw any) map[string]string {
	out := map[string]string{}
	if raw == nil {
		return out
	}
	switch v := raw.(type) {
	case map[string]string:
		for key, val := range v {
			if key = normalizeEnvOverrideKey(key); key != "" {
				out[key] = val
			}
		}
	case map[string]any:
		for key, val := range v {
			if key = normalizeEnvOverrideKey(key); key != "" {
				out[key] = fmt.Sprint(val)
			}
		}
	}
	return out
}

func normalizeEnvOverrideKey(key string) string {
	key = strings.TrimSpace(key)
	if key == "" || !envKeyPattern.MatchString(key) {
		return ""
	}
	return key
}

func loadUserScopeVariableGroupsByID(ctx context.Context, db *sql.DB, userScopeID string, groupIDs []int) (map[string]string, error) {
	if len(groupIDs) == 0 {
		return map[string]string{}, nil
	}
	placeholders := make([]string, 0, len(groupIDs))
	args := make([]any, 0, len(groupIDs)+1)
	args = append(args, userScopeID)
	for i, id := range groupIDs {
		placeholders = append(placeholders, fmt.Sprintf("$%d", i+2))
		args = append(args, id)
	}
	query := fmt.Sprintf(`SELECT id, variables FROM sf_user_scope_variable_groups WHERE user_id=$1 AND id IN (%s)`, strings.Join(placeholders, ","))

	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		log.Printf("variable group env list: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load variable groups").Err()
	}
	defer rows.Close()

	groups := map[int]map[string]string{}
	for rows.Next() {
		var (
			id       int
			rawBytes []byte
		)
		if err := rows.Scan(&id, &rawBytes); err != nil {
			return nil, errs.B().Code(errs.Unavailable).Msg("failed to decode variable groups").Err()
		}
		var parsed map[string]string
		if err := json.Unmarshal(rawBytes, &parsed); err != nil {
			continue
		}
		groups[id] = parsed
	}
	out := map[string]string{}
	for _, id := range groupIDs {
		if vars, ok := groups[id]; ok {
			for k, v := range vars {
				if key := normalizeEnvOverrideKey(k); key != "" {
					out[key] = v
				}
			}
		}
	}
	return out, nil
}

func loadUserVariableGroupsByID(ctx context.Context, db *sql.DB, username string, groupIDs []int) (map[string]string, error) {
	if len(groupIDs) == 0 {
		return map[string]string{}, nil
	}
	placeholders := make([]string, 0, len(groupIDs))
	args := make([]any, 0, len(groupIDs)+1)
	args = append(args, username)
	for i, id := range groupIDs {
		placeholders = append(placeholders, fmt.Sprintf("$%d", i+2))
		args = append(args, id)
	}
	query := fmt.Sprintf(`SELECT id, variables FROM sf_user_variable_groups WHERE username=$1 AND id IN (%s)`, strings.Join(placeholders, ","))

	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		log.Printf("user variable group env list: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load variable groups").Err()
	}
	defer rows.Close()

	groups := map[int]map[string]string{}
	for rows.Next() {
		var (
			id       int
			rawBytes []byte
		)
		if err := rows.Scan(&id, &rawBytes); err != nil {
			return nil, errs.B().Code(errs.Unavailable).Msg("failed to decode variable groups").Err()
		}
		var parsed map[string]string
		if err := json.Unmarshal(rawBytes, &parsed); err != nil {
			continue
		}
		groups[id] = parsed
	}
	out := map[string]string{}
	for _, id := range groupIDs {
		if vars, ok := groups[id]; ok {
			for k, v := range vars {
				if key := normalizeEnvOverrideKey(k); key != "" {
					out[key] = v
				}
			}
		}
	}
	return out, nil
}
