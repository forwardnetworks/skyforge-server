package taskengine

import (
	"context"
	"fmt"
	"strings"
	"time"

	"encore.app/internal/taskstore"
)

func (e *Engine) getTaskMetadataString(ctx context.Context, taskID int, key string) (string, bool, error) {
	if e == nil || e.db == nil || taskID <= 0 {
		return "", false, nil
	}
	key = strings.TrimSpace(key)
	if key == "" {
		return "", false, nil
	}
	ctxReq, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	task, err := taskstore.GetTask(ctxReq, e.db, taskID)
	if err != nil || task == nil {
		return "", false, err
	}
	raw, ok := task.Metadata[key]
	if !ok || len(raw) == 0 {
		return "", false, nil
	}
	val := strings.TrimSpace(string(raw))
	// taskstore metadata values are JSON. If the key is stored as a JSON string, trim quotes.
	if len(val) >= 2 && strings.HasPrefix(val, "\"") && strings.HasSuffix(val, "\"") {
		val = strings.Trim(val, "\"")
	}
	if strings.TrimSpace(val) == "" {
		return "", false, nil
	}
	return fmt.Sprintf("%s", val), true, nil
}
