package maintenance

import (
	"encore.dev/pubsub"
)

type MaintenanceEvent struct {
	// Kind is the job type being requested.
	Kind string `json:"kind" pubsub-attr:"kind"`
}

var Topic = pubsub.NewTopic[*MaintenanceEvent]("skyforge-maintenance", pubsub.TopicConfig{
	DeliveryGuarantee: pubsub.AtLeastOnce,
	OrderingAttribute: "kind",
})
