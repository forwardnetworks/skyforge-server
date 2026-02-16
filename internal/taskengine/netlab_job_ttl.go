package taskengine

const defaultNetlabJobTTLSeconds = 3600

func netlabJobTTLSeconds(env map[string]string) int {
	ttl := envInt(env, "SKYFORGE_NETLAB_JOB_TTL_SECONDS", defaultNetlabJobTTLSeconds)
	if ttl < 0 {
		return defaultNetlabJobTTLSeconds
	}
	return ttl
}
