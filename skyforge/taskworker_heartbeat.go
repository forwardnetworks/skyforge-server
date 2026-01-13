package skyforge

import (
	"context"
	"os"
	"strings"
	"time"

	"encore.dev/rlog"
)

func redisTaskWorkerHeartbeatKey(cfg Config, instance string) string {
	prefix := strings.TrimSpace(cfg.Redis.KeyPrefix)
	if prefix == "" {
		prefix = "skyforge"
	}
	instance = strings.TrimSpace(instance)
	if instance == "" {
		instance = "unknown"
	}
	return prefix + ":taskworker-heartbeat:" + instance
}

func countTaskWorkerHeartbeats(cfg Config) int {
	if redisClient == nil {
		return 0
	}
	prefix := strings.TrimSpace(cfg.Redis.KeyPrefix)
	if prefix == "" {
		prefix = "skyforge"
	}
	pattern := prefix + ":taskworker-heartbeat:*"

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var cursor uint64
	count := 0
	for {
		keys, next, err := redisClient.Scan(ctx, cursor, pattern, 200).Result()
		if err != nil {
			return 0
		}
		count += len(keys)
		cursor = next
		if cursor == 0 || count > 1000 {
			break
		}
	}
	return count
}

func startTaskWorkerHeartbeat(cfg Config) {
	if !cfg.TaskWorkerEnabled || redisClient == nil {
		return
	}
	instance := strings.TrimSpace(os.Getenv("POD_NAME"))
	if instance == "" {
		instance = strings.TrimSpace(os.Getenv("HOSTNAME"))
	}
	if instance == "" {
		if h, err := os.Hostname(); err == nil {
			instance = strings.TrimSpace(h)
		}
	}
	key := redisTaskWorkerHeartbeatKey(cfg, instance)

	// Keep this lightweight: a small Redis write every 15s with TTL 45s.
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()

		for {
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			_ = redisClient.Set(ctx, key, time.Now().UTC().Format(time.RFC3339Nano), 45*time.Second).Err()
			cancel()
			select {
			case <-ticker.C:
				continue
			}
		}
	}()
	rlog.Info("task worker heartbeat enabled", "instance", instance)
}
