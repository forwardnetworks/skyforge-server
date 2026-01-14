package skyforge

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/stdlib"
)

const (
	pgNotifyTasksChannel     = "skyforge_task_updates"
	pgNotifyDashboardChannel = "skyforge_dashboard_updates"
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

func ensurePGNotifyHub(db *sql.DB) *pgNotifyHub {
	if db != nil && globalPGNotifyHub.db == nil {
		globalPGNotifyHub.db = db
	}
	globalPGNotifyHub.startOnce.Do(func() {
		go globalPGNotifyHub.run()
	})
	return globalPGNotifyHub
}

func (h *pgNotifyHub) subscribe(ctx context.Context) <-chan pgNotification {
	ch := make(chan pgNotification, 32)
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
	// Wait for DB handle to be populated (initService sets defaultService/db).
	for h.db == nil {
		time.Sleep(250 * time.Millisecond)
	}

	backoff := 250 * time.Millisecond
	for {
		if err := h.listenOnce(context.Background()); err != nil {
			time.Sleep(backoff)
			if backoff < 10*time.Second {
				backoff *= 2
			}
			continue
		}
		backoff = 250 * time.Millisecond
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

	return sqlConn.Raw(func(dc any) error {
		c, ok := dc.(*stdlib.Conn)
		if !ok || c == nil {
			return fmt.Errorf("unexpected db driver conn type: %T", dc)
		}
		conn := c.Conn()
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
	})
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
