package worker

import (
	"context"

	"encore.app/internal/taskengine"
	"encore.app/internal/taskqueue"
	"encore.app/internal/taskstore"
	"encore.dev/pubsub"
	"encore.dev/rlog"
)

var taskCancelSubscription = pubsub.NewSubscription(taskqueue.CancelTopic, "skyforge-task-worker-cancel", pubsub.SubscriptionConfig[*taskqueue.TaskCancelEvent]{
	Handler:        pubsub.MethodHandler((*Service).handleTaskCancel),
	MaxConcurrency: 16,
})

func (s *Service) handleTaskCancel(ctx context.Context, msg *taskqueue.TaskCancelEvent) error {
	if msg == nil || msg.TaskID <= 0 {
		return nil
	}
	if !workerEncoreCfg.TaskWorkerEnabled {
		return nil
	}
	stdlib, err := getWorkerDB(ctx)
	if err != nil {
		return err
	}
	rec, err := taskstore.GetTask(ctx, stdlib, msg.TaskID)
	if err != nil || rec == nil {
		return nil
	}
	eng := taskengine.New(getWorkerCoreCfg(), stdlib)
	eng.CancelTask(ctx, rec, rlogLogger{})
	rlog.Info("task cancel handled", "task_id", msg.TaskID)
	return nil
}
