package taskrunner

import (
	"context"
	"fmt"
	"sync"
)

type Runner struct {
	name        string
	concurrency int
	queue       chan int

	runOnce sync.Once

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
						continue
					}
					// Use an independent background context for long-running tasks.
					_ = r.exec(context.Background(), taskID)
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
	select {
	case r.queue <- taskID:
		return nil
	default:
		return fmt.Errorf("%s runner queue full", r.name)
	}
}
