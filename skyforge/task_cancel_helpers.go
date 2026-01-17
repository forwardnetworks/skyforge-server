package skyforge

import (
	"context"
	"fmt"
	"strings"

	"encore.app/internal/taskstore"
)

func (s *Service) taskCanceled(ctx context.Context, taskID int) (bool, map[string]any) {
	if taskID <= 0 || s.db == nil {
		return false, nil
	}
	rec, err := getTask(ctx, s.db, taskID)
	if err != nil || rec == nil {
		return false, nil
	}
	meta, _ := fromJSONMap(rec.Metadata)
	if strings.EqualFold(rec.Status, "canceled") {
		return true, meta
	}
	return false, meta
}

func (s *Service) appendTaskWarning(taskID int, warning string) {
	if s == nil || s.db == nil || taskID <= 0 {
		return
	}
	warning = strings.TrimSpace(warning)
	if warning == "" {
		return
	}

	rec, err := getTask(context.Background(), s.db, taskID)
	if err != nil || rec == nil {
		return
	}
	meta, _ := fromJSONMap(rec.Metadata)
	if meta == nil {
		meta = map[string]any{}
	}

	var warnings []any
	if existing, ok := meta["warnings"].([]any); ok {
		warnings = existing
	}
	if warnings == nil {
		warnings = []any{}
	}
	for _, existing := range warnings {
		if strings.EqualFold(strings.TrimSpace(fmt.Sprintf("%v", existing)), warning) {
			meta["warningCount"] = len(warnings)
			if metaJSON, err := toJSONMap(meta); err == nil {
				_ = taskstore.UpdateTaskMetadata(context.Background(), s.db, taskID, metaJSON)
			}
			return
		}
	}
	warnings = append(warnings, warning)
	meta["warnings"] = warnings
	meta["warningCount"] = len(warnings)
	if metaJSON, err := toJSONMap(meta); err == nil {
		_ = taskstore.UpdateTaskMetadata(context.Background(), s.db, taskID, metaJSON)
	}
}
