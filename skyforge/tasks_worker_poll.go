package skyforge

import (
	"context"
	"database/sql"
	"log"
	"sync"
	"time"
)

func (s *Service) startTaskWorkerPoller() {
	if s == nil || s.db == nil {
		return
	}

	go func() {
		log.Printf("task worker enabled: polling queued tasks")

		// Best-effort cleanup so stuck tasks don't block perceived progress.
		{
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			_ = reconcileRunningTasks(ctx, s)
			cancel()
		}

		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			_ = s.processQueuedTasksOnce(ctx, 20, 4)
			cancel()
		}
	}()

	// Encore cron jobs do not run in all self-hosted configurations.
	// Keep a lightweight in-process reconciler loop to avoid stranded tasks.
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			_ = reconcileRunningTasks(ctx, s)
			cancel()
		}
	}()
}

func (s *Service) processQueuedTasksOnce(ctx context.Context, limit int, concurrency int) error {
	if s == nil || s.db == nil {
		return nil
	}
	if limit <= 0 {
		limit = 10
	}
	if concurrency <= 0 {
		concurrency = 1
	}

	taskIDs, err := listQueuedTaskIDs(ctx, s.db, limit)
	if err != nil || len(taskIDs) == 0 {
		return err
	}

	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for _, id := range taskIDs {
		taskID := id
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			_ = s.processQueuedTask(context.Background(), taskID)
		}()
	}
	wg.Wait()
	return nil
}

func listQueuedTaskIDs(ctx context.Context, db *sql.DB, limit int) ([]int, error) {
	if db == nil {
		return nil, errDBUnavailable
	}
	if limit <= 0 {
		limit = 10
	}
	rows, err := db.QueryContext(ctx, `SELECT id
FROM sf_tasks
WHERE status='queued'
ORDER BY id ASC
LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]int, 0, limit)
	for rows.Next() {
		var id int
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		if id > 0 {
			out = append(out, id)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
