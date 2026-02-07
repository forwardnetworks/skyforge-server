package maintenance

import (
	"os"

	"encore.dev/pubsub"
)

type MaintenanceEvent struct {
	// Kind is the job type being requested.
	Kind string `json:"kind" pubsub-attr:"kind"`
}

func newTopic[T any](name string, cfg pubsub.TopicConfig) *pubsub.Topic[T] {
	// In plain `go test` the Encore SDK stubs panic. Avoid that by returning nil.
	if os.Getenv("ENCORE_CFG") == "" {
		return nil
	}
	return pubsub.NewTopic[T](name, cfg)
}

var Topic = newTopic[*MaintenanceEvent]("skyforge-maintenance", pubsub.TopicConfig{
	DeliveryGuarantee: pubsub.AtLeastOnce,
	OrderingAttribute: "kind",
})
