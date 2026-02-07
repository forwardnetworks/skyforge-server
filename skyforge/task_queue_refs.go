package skyforge

import (
	"os"

	"encore.app/internal/taskqueue"
	"encore.dev/pubsub"
)

// NOTE: Even though the topics are defined in internal/taskqueue, Encore requires
// each service that publishes to a topic to obtain a service-scoped reference via
// pubsub.TopicRef.
var taskQueueInteractiveTopic = func() pubsub.Publisher[*taskqueue.TaskEnqueuedEvent] {
	// In plain `go test` the Encore SDK stubs panic. Avoid that by returning nil.
	if os.Getenv("ENCORE_CFG") == "" {
		return nil
	}
	return pubsub.TopicRef[pubsub.Publisher[*taskqueue.TaskEnqueuedEvent]](taskqueue.InteractiveTopic)
}()

var taskQueueBackgroundTopic = func() pubsub.Publisher[*taskqueue.TaskEnqueuedEvent] {
	// In plain `go test` the Encore SDK stubs panic. Avoid that by returning nil.
	if os.Getenv("ENCORE_CFG") == "" {
		return nil
	}
	return pubsub.TopicRef[pubsub.Publisher[*taskqueue.TaskEnqueuedEvent]](taskqueue.BackgroundTopic)
}()
