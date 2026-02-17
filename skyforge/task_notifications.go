package skyforge

import (
	"context"
	"fmt"
	"strings"
	"time"
)

func (s *Service) notifyTaskEvent(ctx context.Context, task *TaskRecord, status string, errMsg string) error {
	if s == nil || s.db == nil || task == nil || !task.DeploymentID.Valid {
		return nil
	}
	// Only notify on deployment-level tasks for now (matches UI expectations).
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	meta, _ := fromJSONMap(task.Metadata)
	action := strings.TrimSpace(metaString(meta, "action"))
	deploymentName := strings.TrimSpace(metaString(meta, "deployment"))
	template := strings.TrimSpace(metaString(meta, "template"))
	serverName := strings.TrimSpace(metaString(meta, "server"))

	if deploymentName == "" {
		deploymentName = task.DeploymentID.String
	}

	title := ""
	message := ""
	priority := "low"
	typ := "DEPLOYMENT"
	category := "deployment"
	referenceID := fmt.Sprintf("%s:%d", task.DeploymentID.String, task.ID)

	switch strings.ToLower(strings.TrimSpace(status)) {
	case "running":
		title = fmt.Sprintf("Deployment %s started", deploymentName)
		message = strings.TrimSpace(fmt.Sprintf("action=%s template=%s server=%s task=%d", action, template, serverName, task.ID))
	case "success":
		title = fmt.Sprintf("Deployment %s succeeded", deploymentName)
		message = strings.TrimSpace(fmt.Sprintf("action=%s task=%d", action, task.ID))
	case "failed":
		title = fmt.Sprintf("Deployment %s failed", deploymentName)
		priority = "high"
		if strings.TrimSpace(errMsg) == "" {
			errMsg = task.Error.String
		}
		message = strings.TrimSpace(fmt.Sprintf("action=%s task=%d error=%s", action, task.ID, strings.TrimSpace(errMsg)))
	case "canceled":
		title = fmt.Sprintf("Deployment %s canceled", deploymentName)
		message = strings.TrimSpace(fmt.Sprintf("action=%s task=%d", action, task.ID))
	default:
		return nil
	}

	_, _, userContext, err := s.loadOwnerContextByKey(task.OwnerID)
	if err != nil {
		// Fall back to notifying just the actor.
		_, err := createNotification(ctx, s.db, task.CreatedBy, title, message, typ, category, referenceID, priority)
		return err
	}

	recipients := ownerNotificationRecipients(userContext)
	if len(recipients) == 0 {
		recipients = []string{task.CreatedBy}
	}
	for _, username := range recipients {
		if _, err := createNotification(ctx, s.db, username, title, message, typ, category, referenceID, priority); err != nil {
			return err
		}
	}
	return nil
}
