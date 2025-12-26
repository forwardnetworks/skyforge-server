package skyforge

import (
	"context"
	"database/sql"
	"strconv"
	"strings"
	"time"

	"encore.dev/beta/auth"
	"encore.dev/beta/errs"
)

type NotificationCreateParams struct {
	UserID      string `json:"user_id"`
	Username    string `json:"username"`
	Title       string `json:"title"`
	Message     string `json:"message,omitempty"`
	Type        string `json:"type,omitempty"`
	Category    string `json:"category,omitempty"`
	ReferenceID string `json:"reference_id,omitempty"`
	Priority    string `json:"priority,omitempty"`
}

type NotificationCreateResponse struct {
	ID string `json:"id"`
}

type NotificationListParams struct {
	IncludeRead string `query:"include_read" encore:"optional"`
	Limit       string `query:"limit" encore:"optional"`
}

type NotificationListResponse struct {
	Notifications []NotificationRecord `json:"notifications"`
}

type NotificationStatusResponse struct {
	Status string `json:"status"`
}

type NotificationSettingsUpdateParams struct {
	PollingEnabled    bool  `json:"pollingEnabled"`
	PollingIntervalMs int64 `json:"pollingIntervalMs"`
}

func requireAuthUser() (*AuthUser, error) {
	data := auth.Data()
	if data == nil {
		return nil, errs.B().Code(errs.Unauthenticated).Msg("authentication required").Err()
	}
	user, ok := data.(*AuthUser)
	if !ok || user == nil {
		return nil, errs.B().Code(errs.Internal).Msg("invalid auth data").Err()
	}
	return user, nil
}

// GetPublicNotificationSettings retrieves notification settings for authenticated users.
//
//encore:api auth method=GET path=/system/settings/notifications/public
func (s *Service) GetPublicNotificationSettings(ctx context.Context) (*NotificationSettings, error) {
	settings, err := notificationSettings(ctx, s.db, s.cfg)
	if err != nil {
		return nil, errs.B().Code(errs.Internal).Msg("failed to load notification settings").Err()
	}
	return &settings, nil
}

// GetNotificationSettings retrieves notification settings (admin only).
//
//encore:api auth method=GET path=/system/settings/notifications tag:admin
func (s *Service) GetNotificationSettings(ctx context.Context) (*NotificationSettings, error) {
	settings, err := notificationSettings(ctx, s.db, s.cfg)
	if err != nil {
		return nil, errs.B().Code(errs.Internal).Msg("failed to load notification settings").Err()
	}
	return &settings, nil
}

// UpdateNotificationSettings updates notification settings (admin only).
//
//encore:api auth method=PUT path=/system/settings/notifications tag:admin
func (s *Service) UpdateNotificationSettings(ctx context.Context, params *NotificationSettingsUpdateParams) (*NotificationSettings, error) {
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("settings store unavailable").Err()
	}
	if params == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid payload").Err()
	}
	if params.PollingIntervalMs < 1000 {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("polling interval must be >= 1000ms").Err()
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	if err := upsertSetting(ctx, s.db, "notifications_polling_enabled", strconv.FormatBool(params.PollingEnabled)); err != nil {
		return nil, errs.B().Code(errs.Internal).Msg("failed to update notification settings").Err()
	}
	if err := upsertSetting(ctx, s.db, "notifications_polling_interval", strconv.FormatInt(params.PollingIntervalMs, 10)); err != nil {
		return nil, errs.B().Code(errs.Internal).Msg("failed to update notification settings").Err()
	}
	settings, err := notificationSettings(ctx, s.db, s.cfg)
	if err != nil {
		return nil, errs.B().Code(errs.Internal).Msg("failed to load notification settings").Err()
	}
	return &settings, nil
}

// CreateNotification creates a new notification.
//
//encore:api auth method=POST path=/notifications
func (s *Service) CreateNotification(ctx context.Context, params *NotificationCreateParams) (*NotificationCreateResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("notification store unavailable").Err()
	}
	if params == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid payload").Err()
	}
	target := strings.TrimSpace(params.UserID)
	if target == "" {
		target = strings.TrimSpace(params.Username)
	}
	if target == "" {
		target = user.Username
	}
	if !strings.EqualFold(target, user.Username) && !user.IsAdmin {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	id, err := createNotification(
		ctx,
		s.db,
		target,
		params.Title,
		params.Message,
		params.Type,
		params.Category,
		params.ReferenceID,
		params.Priority,
	)
	if err != nil {
		return nil, errs.B().Code(errs.Internal).Msg("failed to create notification").Err()
	}
	return &NotificationCreateResponse{ID: id}, nil
}

// GetUserNotifications retrieves notifications for a specific user.
//
//encore:api auth method=GET path=/notifications/for-user/:userID
func (s *Service) GetUserNotifications(ctx context.Context, userID string, params *NotificationListParams) (*NotificationListResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(userID, user.Username) && !user.IsAdmin {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	includeRead := false
	limit := 25
	if params != nil {
		if strings.EqualFold(strings.TrimSpace(params.IncludeRead), "true") || strings.TrimSpace(params.IncludeRead) == "1" {
			includeRead = true
		}
		if raw := strings.TrimSpace(params.Limit); raw != "" {
			if v, err := strconv.Atoi(raw); err == nil && v > 0 && v <= 100 {
				limit = v
			}
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	notifications, err := listNotifications(ctx, s.db, userID, includeRead, limit)
	if err != nil {
		return nil, errs.B().Code(errs.Internal).Msg("failed to load notifications").Err()
	}
	return &NotificationListResponse{Notifications: notifications}, nil
}

// MarkAllNotificationsAsRead marks all notifications for a user as read.
//
//encore:api auth method=PUT path=/notifications/for-user/:userID/read-all
func (s *Service) MarkAllNotificationsAsRead(ctx context.Context, userID string) (*NotificationStatusResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(userID, user.Username) && !user.IsAdmin {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := markAllNotificationsRead(ctx, s.db, userID); err != nil {
		return nil, errs.B().Code(errs.Internal).Msg("failed to mark notifications read").Err()
	}
	return &NotificationStatusResponse{Status: "ok"}, nil
}

// MarkNotificationAsRead marks a notification as read.
//
//encore:api auth method=PUT path=/notifications/single/:id/read
func (s *Service) MarkNotificationAsRead(ctx context.Context, id string) (*NotificationStatusResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := markNotificationRead(ctx, s.db, user.Username, id); err != nil {
		if err == sql.ErrNoRows {
			return nil, errs.B().Code(errs.NotFound).Msg("notification not found").Err()
		}
		return nil, errs.B().Code(errs.Internal).Msg("failed to mark notification read").Err()
	}
	return &NotificationStatusResponse{Status: "ok"}, nil
}

// DeleteNotification deletes a notification.
//
//encore:api auth method=DELETE path=/notifications/single/:id
func (s *Service) DeleteNotification(ctx context.Context, id string) (*NotificationStatusResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := deleteNotification(ctx, s.db, user.Username, id); err != nil {
		if err == sql.ErrNoRows {
			return nil, errs.B().Code(errs.NotFound).Msg("notification not found").Err()
		}
		return nil, errs.B().Code(errs.Internal).Msg("failed to delete notification").Err()
	}
	return &NotificationStatusResponse{Status: "ok"}, nil
}
