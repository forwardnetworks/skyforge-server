package taskengine

import (
	"context"
	"fmt"
	"strings"

	"encore.app/internal/taskdispatch"
)

func (e *Engine) runNetlabC9sAnsible(ctx context.Context, spec netlabC9sRunSpec, ns, topologyName, labName string, log Logger) error {
	if log == nil {
		log = noopLogger{}
	}
	if strings.TrimSpace(e.cfg.AnsibleRunnerImage) == "" {
		return fmt.Errorf("netlab-c9s ansible requested but AnsibleRunnerImage is not configured (set ENCORE_CFG_SKYFORGE.NetlabGenerator.AnsibleImage or SKYFORGE_ANSIBLE_RUNNER_IMAGE)")
	}
	return taskdispatch.WithTaskStep(ctx, e.db, spec.TaskID, "netlab.c9s.ansible", func() error {
		log.Infof("Netlab C9s Ansible phase is not implemented yet (topology=%s namespace=%s)", strings.TrimSpace(topologyName), strings.TrimSpace(ns))
		return fmt.Errorf("netlab-c9s ansible phase not implemented yet")
	})
}
