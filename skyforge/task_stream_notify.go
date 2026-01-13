package skyforge

import (
	"context"
	"fmt"
	"time"
)

func taskUpdateChannel(taskID int) string {
	return fmt.Sprintf("skyforge:task:%d", taskID)
}

func dashboardUpdateChannel() string {
	return "skyforge:dashboard"
}

func publishTaskUpdate(taskID int) {
	if taskID <= 0 || redisClient == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	_ = redisClient.Publish(ctx, taskUpdateChannel(taskID), "1").Err()
	_ = redisClient.Publish(ctx, dashboardUpdateChannel(), "1").Err()
}
