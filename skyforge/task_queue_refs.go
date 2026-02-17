package skyforge

import (
	"encore.app/internal/taskqueue"
	"encore.dev/pubsub"
)

// NOTE: Even though the topics are defined in internal/taskqueue, Encore requires
// each service that publishes to a topic to obtain a service-local reference via
// pubsub.TopicRef.
var taskQueueInteractiveTopic = pubsub.TopicRef[pubsub.Publisher[*taskqueue.TaskEnqueuedEvent]](taskqueue.InteractiveTopic)

var taskQueueBackgroundTopic = pubsub.TopicRef[pubsub.Publisher[*taskqueue.TaskEnqueuedEvent]](taskqueue.BackgroundTopic)
