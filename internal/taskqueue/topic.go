package taskqueue

import "encore.dev/pubsub"

type TaskEnqueuedEvent struct {
	// Key preserves per-deployment ordering best-effort.
	Key string `json:"key,omitempty" pubsub-attr:"key"`
	// TaskID is the sf_tasks.id being queued.
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

// Topic is kept for backward compatibility; new code should choose interactive/background.
var Topic = InteractiveTopic
