package taskqueue

import "encore.dev/pubsub"

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

var InteractiveTopic = pubsub.NewTopic[*TaskEnqueuedEvent]("skyforge-task-queue-interactive", pubsub.TopicConfig{
	DeliveryGuarantee: pubsub.AtLeastOnce,
	OrderingAttribute: "key",
})

var BackgroundTopic = pubsub.NewTopic[*TaskEnqueuedEvent]("skyforge-task-queue-background", pubsub.TopicConfig{
	DeliveryGuarantee: pubsub.AtLeastOnce,
	OrderingAttribute: "key",
})

var CancelTopic = pubsub.NewTopic[*TaskCancelEvent]("skyforge-task-cancel", pubsub.TopicConfig{
	DeliveryGuarantee: pubsub.AtLeastOnce,
})
