package taskrunner

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestRunner_SubmitInvalid(t *testing.T) {
	r := New("test", 1, 1, func(context.Context, int) error { return nil })
	if err := r.Submit(0); err == nil {
		t.Fatal("expected error for invalid task id")
	}
}

func TestRunner_ExecutesTask(t *testing.T) {
	var ran int32
	r := New("test", 1, 10, func(ctx context.Context, taskID int) error {
		atomic.AddInt32(&ran, 1)
		return nil
	})
	if err := r.Submit(1); err != nil {
		t.Fatalf("submit failed: %v", err)
	}

	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-deadline.C:
			t.Fatalf("task did not run, ran=%d", atomic.LoadInt32(&ran))
		case <-tick.C:
			if atomic.LoadInt32(&ran) > 0 {
				return
			}
		}
	}
}

func TestRunner_DedupesQueuedTaskID(t *testing.T) {
	var ran int32
	block := make(chan struct{})
	r := New("test", 1, 10, func(ctx context.Context, taskID int) error {
		atomic.AddInt32(&ran, 1)
		<-block
		return nil
	})

	if err := r.Submit(42); err != nil {
		t.Fatalf("submit failed: %v", err)
	}
	if err := r.Submit(42); err != nil {
		t.Fatalf("duplicate submit should not fail: %v", err)
	}
	if err := r.Submit(42); err != nil {
		t.Fatalf("duplicate submit should not fail: %v", err)
	}

	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	for {
		if atomic.LoadInt32(&ran) == 1 {
			break
		}
		select {
		case <-deadline.C:
			t.Fatalf("expected exactly one execution while queued, got=%d", atomic.LoadInt32(&ran))
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}
	close(block)
}
