package taskrunner

import (
	"context"
	"fmt"
	"sync"

	"encore.dev/rlog"
)

type Runner struct {
	name        string
	concurrency int
	queue       chan int
	enqueued    map[int]struct{}

	runOnce sync.Once
	mu      sync.Mutex

	exec func(context.Context, int) error
}

func New(name string, concurrency int, queueSize int, exec func(context.Context, int) error) *Runner {
	if concurrency <= 0 {
		concurrency = 1
	}
	if queueSize <= 0 {
		queueSize = concurrency * 2
	}
	return &Runner{
		name:        name,
		concurrency: concurrency,
		queue:       make(chan int, queueSize),
		enqueued:    map[int]struct{}{},
		exec:        exec,
	}
}

func (r *Runner) Start() {
	if r == nil {
		return
	}
	r.runOnce.Do(func() {
		for i := 0; i < r.concurrency; i++ {
			go func() {
				for taskID := range r.queue {
					if taskID <= 0 {
						continue
					}
					if r.exec == nil {
						r.clearEnqueued(taskID)
						continue
					}
					// Use an independent background context for long-running tasks.
					if err := r.exec(context.Background(), taskID); err != nil {
						rlog.Error("task runner exec failed", "runner", r.name, "task_id", taskID, "err", err)
					}
					r.clearEnqueued(taskID)
				}
			}()
		}
	})
}

func (r *Runner) Submit(taskID int) error {
	if r == nil {
		return fmt.Errorf("runner is nil")
	}
	if taskID <= 0 {
		return fmt.Errorf("invalid task id")
	}
	r.Start()
	if !r.markEnqueued(taskID) {
		// Already queued/running in this process.
		return nil
	}
	select {
	case r.queue <- taskID:
		return nil
	default:
		r.clearEnqueued(taskID)
		return fmt.Errorf("%s runner queue full", r.name)
	}
}

func (r *Runner) markEnqueued(taskID int) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.enqueued[taskID]; ok {
		return false
	}
	r.enqueued[taskID] = struct{}{}
	return true
}

func (r *Runner) clearEnqueued(taskID int) {
	r.mu.Lock()
	delete(r.enqueued, taskID)
	r.mu.Unlock()
}
