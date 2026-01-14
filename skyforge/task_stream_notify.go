package skyforge

import (
	"context"
	"database/sql"
	"fmt"
)

func taskUpdateChannel(taskID int) string {
	return fmt.Sprintf("skyforge:task:%d", taskID)
}

func dashboardUpdateChannel() string {
	return "skyforge:dashboard"
}

func publishTaskUpdate(ctx context.Context, db *sql.DB, taskID int) {
	if taskID <= 0 {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	_ = notifyTaskUpdatePG(ctx, db, taskID)
	_ = notifyDashboardUpdatePG(ctx, db)
}
