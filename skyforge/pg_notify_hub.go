package skyforge

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

const (
	pgNotifyTasksChannel         = "skyforge_task_updates"
	pgNotifyDashboardChannel     = "skyforge_dashboard_updates"
	pgNotifyNotificationsChannel = "skyforge_notification_updates"
	pgNotifyWebhooksChannel      = "skyforge_webhook_updates"
	pgNotifySyslogChannel        = "skyforge_syslog_updates"
	pgNotifySnmpChannel          = "skyforge_snmp_updates"
	pgNotifyUsersChannel         = "skyforge_scopes_updates"
	pgNotifyDeploymentEventsChan = "skyforge_deployment_events"
)

type pgNotification struct {
	Channel string
	Payload string
}

type pgNotifyHub struct {
	db *sql.DB

	mu   sync.RWMutex
	subs map[chan pgNotification]struct{}

	startOnce sync.Once
}

var globalPGNotifyHub = &pgNotifyHub{
	subs: make(map[chan pgNotification]struct{}),
}

var errPGNotifyUnsupportedDriver = errors.New("pg notify hub unsupported db driver")

func ensurePGNotifyHub(db *sql.DB) *pgNotifyHub {
	if db != nil {
		if globalPGNotifyHub.db == nil {
			globalPGNotifyHub.db = db
		}
		globalPGNotifyHub.startOnce.Do(func() {
			go globalPGNotifyHub.run()
		})
	}
	return globalPGNotifyHub
}

func (h *pgNotifyHub) subscribe(ctx context.Context) <-chan pgNotification {
	ch := make(chan pgNotification, 256)
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	h.mu.Unlock()

	go func() {
		<-ctx.Done()
		h.mu.Lock()
		delete(h.subs, ch)
		h.mu.Unlock()
		close(ch)
	}()

	return ch
}

func (h *pgNotifyHub) broadcast(n pgNotification) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for ch := range h.subs {
		select {
		case ch <- n:
		default:
			// Best-effort: if a subscriber falls behind, drop signals.
		}
	}
}

func (h *pgNotifyHub) run() {
	if h.db == nil {
		return
	}

	backoff := 250 * time.Millisecond
	lastLog := time.Time{}
	for {
		if err := h.listenOnce(context.Background()); err != nil {
			// Avoid log spam if the DB is unavailable; report occasionally while backing off.
			if time.Since(lastLog) > 30*time.Second {
				log.Printf("pg notify hub listen failed (backing off): %v", err)
				lastLog = time.Now()
			}
			time.Sleep(backoff)
			if backoff < 10*time.Second {
				backoff *= 2
			}
			continue
		}
		backoff = 250 * time.Millisecond
		lastLog = time.Time{}
	}
}

func (h *pgNotifyHub) listenOnce(ctx context.Context) error {
	if h.db == nil {
		return fmt.Errorf("pg notify hub missing db")
	}

	sqlConn, err := h.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer sqlConn.Close()

	err = sqlConn.Raw(func(dc any) error {
		c, ok := dc.(*stdlib.Conn)
		if !ok || c == nil {
			return fmt.Errorf("%w: %T", errPGNotifyUnsupportedDriver, dc)
		}
		conn := c.Conn()
		if conn == nil {
			return fmt.Errorf("missing pgx conn")
		}

		return h.listenOnPGX(ctx, conn)
	})
	if errors.Is(err, errPGNotifyUnsupportedDriver) {
		// Encore's stdlib driver wraps the underlying connection; fall back to an explicit pgx connection
		// using the same SKYFORGE_DB_* environment variables used by the app.
		connStr, err2 := pgConnStringFromEnv()
		if err2 != nil {
			return fmt.Errorf("pg notify hub cannot build db conn string: %w", err2)
		}
		conn, err2 := pgx.Connect(ctx, connStr)
		if err2 != nil {
			return err2
		}
		defer conn.Close(ctx)
		return h.listenOnPGX(ctx, conn)
	}
	return err
}

func pgConnStringFromEnv() (string, error) {
	host := strings.TrimSpace(os.Getenv("SKYFORGE_DB_HOST"))
	port := strings.TrimSpace(os.Getenv("SKYFORGE_DB_PORT"))
	name := strings.TrimSpace(os.Getenv("SKYFORGE_DB_NAME"))
	user := strings.TrimSpace(os.Getenv("SKYFORGE_DB_USER"))
	pass := os.Getenv("SKYFORGE_DB_PASSWORD")
	sslmode := strings.TrimSpace(os.Getenv("SKYFORGE_DB_SSLMODE"))
	if sslmode == "" {
		sslmode = "disable"
	}
	if host == "" || port == "" || name == "" || user == "" || strings.TrimSpace(pass) == "" {
		return "", fmt.Errorf("missing SKYFORGE_DB_* env vars")
	}
	// NOTE: do not log this string (contains password).
	return fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s", host, port, user, pass, name, sslmode), nil
}

func (h *pgNotifyHub) listenOnPGX(ctx context.Context, conn *pgx.Conn) error {
	if conn == nil {
		return fmt.Errorf("missing pgx conn")
	}

	// LISTEN uses an implicit transaction; keep it simple with direct Exec.
	if _, err := conn.Exec(ctx, "LISTEN "+pgNotifyTasksChannel); err != nil {
		return err
	}
	if _, err := conn.Exec(ctx, "LISTEN "+pgNotifyDashboardChannel); err != nil {
		return err
	}
	if _, err := conn.Exec(ctx, "LISTEN "+pgNotifyNotificationsChannel); err != nil {
		return err
	}
	if _, err := conn.Exec(ctx, "LISTEN "+pgNotifyWebhooksChannel); err != nil {
		return err
	}
	if _, err := conn.Exec(ctx, "LISTEN "+pgNotifySyslogChannel); err != nil {
		return err
	}
	if _, err := conn.Exec(ctx, "LISTEN "+pgNotifySnmpChannel); err != nil {
		return err
	}
	if _, err := conn.Exec(ctx, "LISTEN "+pgNotifyUsersChannel); err != nil {
		return err
	}
	if _, err := conn.Exec(ctx, "LISTEN "+pgNotifyDeploymentEventsChan); err != nil {
		return err
	}

	for {
		n, err := conn.WaitForNotification(ctx)
		if err != nil {
			return err
		}
		if n == nil {
			continue
		}
		h.broadcast(pgNotification{Channel: n.Channel, Payload: n.Payload})
	}
}

func notifyTaskUpdatePG(ctx context.Context, db *sql.DB, taskID int) error {
	if db == nil || taskID <= 0 {
		return nil
	}
	ctxReq, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()
	_, err := db.ExecContext(ctxReq, "SELECT pg_notify($1, $2)", pgNotifyTasksChannel, strconv.Itoa(taskID))
	return err
}

func notifyDashboardUpdatePG(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return nil
	}
	ctxReq, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()
	_, err := db.ExecContext(ctxReq, "SELECT pg_notify($1, $2)", pgNotifyDashboardChannel, "1")
	return err
}

func notifyNotificationUpdatePG(ctx context.Context, db *sql.DB, username string) error {
	username = strings.ToLower(strings.TrimSpace(username))
	if db == nil || username == "" {
		return nil
	}
	ctxReq, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()
	_, err := db.ExecContext(ctxReq, "SELECT pg_notify($1, $2)", pgNotifyNotificationsChannel, username)
	return err
}

func notifyWebhookUpdatePG(ctx context.Context, db *sql.DB, username string) error {
	username = strings.ToLower(strings.TrimSpace(username))
	if db == nil || username == "" {
		return nil
	}
	ctxReq, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()
	_, err := db.ExecContext(ctxReq, "SELECT pg_notify($1, $2)", pgNotifyWebhooksChannel, username)
	return err
}

func notifySyslogUpdatePG(ctx context.Context, db *sql.DB, username string) error {
	username = strings.ToLower(strings.TrimSpace(username))
	if db == nil || username == "" {
		return nil
	}
	ctxReq, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()
	_, err := db.ExecContext(ctxReq, "SELECT pg_notify($1, $2)", pgNotifySyslogChannel, username)
	return err
}

func notifySnmpUpdatePG(ctx context.Context, db *sql.DB, username string) error {
	username = strings.ToLower(strings.TrimSpace(username))
	if db == nil || username == "" {
		return nil
	}
	ctxReq, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()
	_, err := db.ExecContext(ctxReq, "SELECT pg_notify($1, $2)", pgNotifySnmpChannel, username)
	return err
}

func notifyUsersUpdatePG(ctx context.Context, db *sql.DB, payload string) error {
	payload = strings.ToLower(strings.TrimSpace(payload))
	if payload == "" {
		payload = "*"
	}
	if db == nil {
		return nil
	}
	ctxReq, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()
	_, err := db.ExecContext(ctxReq, "SELECT pg_notify($1, $2)", pgNotifyUsersChannel, payload)
	return err
}

func notifyDeploymentEventPG(ctx context.Context, db *sql.DB, ownerID, deploymentID string) error {
	ownerID = strings.TrimSpace(ownerID)
	deploymentID = strings.TrimSpace(deploymentID)
	if db == nil || ownerID == "" || deploymentID == "" {
		return nil
	}
	ctxReq, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()
	payload := ownerID + ":" + deploymentID
	_, err := db.ExecContext(ctxReq, "SELECT pg_notify($1, $2)", pgNotifyDeploymentEventsChan, payload)
	return err
}

func waitForTaskUpdateSignal(ctx context.Context, db *sql.DB, taskID int) bool {
	if taskID <= 0 {
		return false
	}
	hub := ensurePGNotifyHub(db)
	ch := hub.subscribe(ctx)
	for {
		select {
		case <-ctx.Done():
			return false
		case n, ok := <-ch:
			if !ok {
				return false
			}
			if n.Channel != pgNotifyTasksChannel {
				continue
			}
			if strings.TrimSpace(n.Payload) == strconv.Itoa(taskID) {
				return true
			}
		}
	}
}

func waitForDashboardUpdateSignal(ctx context.Context, db *sql.DB) bool {
	hub := ensurePGNotifyHub(db)
	ch := hub.subscribe(ctx)
	for {
		select {
		case <-ctx.Done():
			return false
		case n, ok := <-ch:
			if !ok {
				return false
			}
			if n.Channel == pgNotifyDashboardChannel {
				return true
			}
		}
	}
}

func waitForNotificationUpdateSignal(ctx context.Context, db *sql.DB, username string) bool {
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" {
		return false
	}
	hub := ensurePGNotifyHub(db)
	ch := hub.subscribe(ctx)
	for {
		select {
		case <-ctx.Done():
			return false
		case n, ok := <-ch:
			if !ok {
				return false
			}
			if n.Channel != pgNotifyNotificationsChannel {
				continue
			}
			if strings.TrimSpace(n.Payload) == username {
				return true
			}
		}
	}
}

func waitForWebhookUpdateSignal(ctx context.Context, db *sql.DB, username string) bool {
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" {
		return false
	}
	hub := ensurePGNotifyHub(db)
	ch := hub.subscribe(ctx)
	for {
		select {
		case <-ctx.Done():
			return false
		case n, ok := <-ch:
			if !ok {
				return false
			}
			if n.Channel != pgNotifyWebhooksChannel {
				continue
			}
			if strings.TrimSpace(n.Payload) == username {
				return true
			}
		}
	}
}

func waitForSyslogUpdateSignal(ctx context.Context, db *sql.DB, username string) bool {
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" {
		return false
	}
	hub := ensurePGNotifyHub(db)
	ch := hub.subscribe(ctx)
	for {
		select {
		case <-ctx.Done():
			return false
		case n, ok := <-ch:
			if !ok {
				return false
			}
			if n.Channel != pgNotifySyslogChannel {
				continue
			}
			if strings.TrimSpace(n.Payload) == username {
				return true
			}
		}
	}
}

func waitForSnmpUpdateSignal(ctx context.Context, db *sql.DB, username string) bool {
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" {
		return false
	}
	hub := ensurePGNotifyHub(db)
	ch := hub.subscribe(ctx)
	for {
		select {
		case <-ctx.Done():
			return false
		case n, ok := <-ch:
			if !ok {
				return false
			}
			if n.Channel != pgNotifySnmpChannel {
				continue
			}
			if strings.TrimSpace(n.Payload) == username {
				return true
			}
		}
	}
}

func waitForUsersUpdateSignal(ctx context.Context, db *sql.DB, username string) bool {
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" {
		return false
	}
	hub := ensurePGNotifyHub(db)
	ch := hub.subscribe(ctx)
	for {
		select {
		case <-ctx.Done():
			return false
		case n, ok := <-ch:
			if !ok {
				return false
			}
			if n.Channel != pgNotifyUsersChannel {
				continue
			}
			payload := strings.ToLower(strings.TrimSpace(n.Payload))
			if payload == "*" || payload == username {
				return true
			}
		}
	}
}

func waitForDeploymentEventSignal(ctx context.Context, db *sql.DB, ownerID, deploymentID string) bool {
	ownerID = strings.TrimSpace(ownerID)
	deploymentID = strings.TrimSpace(deploymentID)
	if ownerID == "" || deploymentID == "" {
		return false
	}
	payloadWant := ownerID + ":" + deploymentID
	hub := ensurePGNotifyHub(db)
	ch := hub.subscribe(ctx)
	for {
		select {
		case <-ctx.Done():
			return false
		case n, ok := <-ch:
			if !ok {
				return false
			}
			if n.Channel != pgNotifyDeploymentEventsChan {
				continue
			}
			if strings.TrimSpace(n.Payload) == payloadWant {
				return true
			}
		}
	}
}
