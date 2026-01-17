package taskengine

import (
	"context"
	"fmt"
	"strings"
	"time"

	"encore.app/internal/taskstore"
)

func (e *Engine) appendTaskWarning(taskID int, warning string) {
	if e == nil || e.db == nil || taskID <= 0 {
		return
	}
	warning = strings.TrimSpace(warning)
	if warning == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	rec, err := taskstore.GetTask(ctx, e.db, taskID)
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
				_ = taskstore.UpdateTaskMetadata(ctx, e.db, taskID, metaJSON)
			}
			return
		}
	}
	warnings = append(warnings, warning)
	meta["warnings"] = warnings
	meta["warningCount"] = len(warnings)
	if metaJSON, err := toJSONMap(meta); err == nil {
		_ = taskstore.UpdateTaskMetadata(ctx, e.db, taskID, metaJSON)
	}
}
