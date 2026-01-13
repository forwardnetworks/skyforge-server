package taskqueue

import "encore.dev/pubsub"

type TaskEnqueuedEvent struct {
	// Key preserves per-deployment ordering best-effort.
	Key string `json:"key,omitempty" pubsub-attr:"key"`
	// TaskID is the sf_tasks.id being queued.
	TaskID int `json:"taskId"`
}

var Topic = pubsub.NewTopic[*TaskEnqueuedEvent]("skyforge-task-queue", pubsub.TopicConfig{
	DeliveryGuarantee: pubsub.AtLeastOnce,
	OrderingAttribute: "key",
})

