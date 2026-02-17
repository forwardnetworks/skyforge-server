package tasknotify

import (
	"context"
	"database/sql"
	"strconv"
	"strings"
	"time"
)

const (
	TasksChannel         = "skyforge_task_updates"
	DashboardChannel     = "skyforge_dashboard_updates"
	NotificationsChannel = "skyforge_notification_updates"
	WebhooksChannel      = "skyforge_webhook_updates"
	SyslogChannel        = "skyforge_syslog_updates"
	SnmpChannel          = "skyforge_snmp_updates"
	UsersChannel         = "skyforge_users_updates"
	DeploymentEventsChan = "skyforge_deployment_events"
)

func NotifyTaskUpdate(ctx context.Context, db *sql.DB, taskID int) error {
	if db == nil || taskID <= 0 {
		return nil
	}
	ctxReq, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()
	_, err := db.ExecContext(ctxReq, "SELECT pg_notify($1, $2)", TasksChannel, strconv.Itoa(taskID))
	return err
}

func NotifyDashboardUpdate(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return nil
	}
	ctxReq, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()
	_, err := db.ExecContext(ctxReq, "SELECT pg_notify($1, $2)", DashboardChannel, "1")
	return err
}

func NotifyNotificationsUpdate(ctx context.Context, db *sql.DB, username string) error {
	username = strings.ToLower(strings.TrimSpace(username))
	if db == nil || username == "" {
		return nil
	}
	ctxReq, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()
	_, err := db.ExecContext(ctxReq, "SELECT pg_notify($1, $2)", NotificationsChannel, username)
	return err
}

func NotifyWebhooksUpdate(ctx context.Context, db *sql.DB, username string) error {
	username = strings.ToLower(strings.TrimSpace(username))
	if db == nil || username == "" {
		return nil
	}
	ctxReq, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()
	_, err := db.ExecContext(ctxReq, "SELECT pg_notify($1, $2)", WebhooksChannel, username)
	return err
}

func NotifySyslogUpdate(ctx context.Context, db *sql.DB, username string) error {
	username = strings.ToLower(strings.TrimSpace(username))
	if db == nil || username == "" {
		return nil
	}
	ctxReq, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()
	_, err := db.ExecContext(ctxReq, "SELECT pg_notify($1, $2)", SyslogChannel, username)
	return err
}

func NotifySnmpUpdate(ctx context.Context, db *sql.DB, username string) error {
	username = strings.ToLower(strings.TrimSpace(username))
	if db == nil || username == "" {
		return nil
	}
	ctxReq, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()
	_, err := db.ExecContext(ctxReq, "SELECT pg_notify($1, $2)", SnmpChannel, username)
	return err
}

func NotifyUsersUpdate(ctx context.Context, db *sql.DB, payload string) error {
	payload = strings.ToLower(strings.TrimSpace(payload))
	if payload == "" {
		payload = "*"
	}
	if db == nil {
		return nil
	}
	ctxReq, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()
	_, err := db.ExecContext(ctxReq, "SELECT pg_notify($1, $2)", UsersChannel, payload)
	return err
}

func NotifyDeploymentEvent(ctx context.Context, db *sql.DB, ownerID, deploymentID string) error {
	ownerID = strings.TrimSpace(ownerID)
	deploymentID = strings.TrimSpace(deploymentID)
	if db == nil || ownerID == "" || deploymentID == "" {
		return nil
	}
	ctxReq, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()
	payload := ownerID + ":" + deploymentID
	_, err := db.ExecContext(ctxReq, "SELECT pg_notify($1, $2)", DeploymentEventsChan, payload)
	return err
}
