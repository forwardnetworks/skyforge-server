package taskqueue

import (
	"os"

	"encore.dev/pubsub"
)

type TaskEnqueuedEvent struct {
	// Key preserves per-deployment ordering best-effort.
	Key string `json:"key,omitempty" pubsub-attr:"key"`
	// TaskID is the sf_tasks.id being queued.
	TaskID int `json:"taskId"`
}

type TaskCancelEvent struct {
	// TaskID is the sf_tasks.id being canceled.
	TaskID int `json:"taskId"`
}

type TaskStatusEvent struct {
	TaskID int    `json:"taskId"`
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

func newTopic[T any](name string, cfg pubsub.TopicConfig) *pubsub.Topic[T] {
	// In plain `go test` the Encore SDK stubs panic. Avoid that by returning nil.
	// These topics are only valid when built/run with `encore` (which provides ENCORE_CFG).
	if os.Getenv("ENCORE_CFG") == "" {
		return nil
	}
	return pubsub.NewTopic[T](name, cfg)
}

var InteractiveTopic = newTopic[*TaskEnqueuedEvent]("skyforge-task-queue-interactive", pubsub.TopicConfig{
	DeliveryGuarantee: pubsub.AtLeastOnce,
	OrderingAttribute: "key",
})

var BackgroundTopic = newTopic[*TaskEnqueuedEvent]("skyforge-task-queue-background", pubsub.TopicConfig{
	DeliveryGuarantee: pubsub.AtLeastOnce,
	OrderingAttribute: "key",
})

var StatusTopic = newTopic[*TaskStatusEvent]("skyforge-task-status", pubsub.TopicConfig{
	DeliveryGuarantee: pubsub.AtLeastOnce,
})

var CancelTopic = newTopic[*TaskCancelEvent]("skyforge-task-cancel", pubsub.TopicConfig{
	DeliveryGuarantee: pubsub.AtLeastOnce,
})
