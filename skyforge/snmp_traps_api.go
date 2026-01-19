package skyforge

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"strconv"
	"strings"
	"time"

	"encore.dev/beta/errs"
	"encore.dev/rlog"
)

type snmpTrapTokenRecord struct {
	Community string
	UpdatedAt time.Time
}

func (s *Service) getSnmpTrapToken(ctx context.Context, username string) (*snmpTrapTokenRecord, error) {
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	if s.box == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("encryption unavailable").Err()
	}
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("username is required").Err()
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	var enc string
	var updated time.Time
	err := s.db.QueryRowContext(ctx, `SELECT community, updated_at FROM sf_snmp_trap_tokens WHERE username=$1`, username).Scan(&enc, &updated)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	plain, err := s.box.decrypt(enc)
	if err != nil {
		s.deleteSnmpTrapToken(ctx, username)
		return nil, nil
	}
	return &snmpTrapTokenRecord{Community: strings.TrimSpace(plain), UpdatedAt: updated}, nil
}

func (s *Service) deleteSnmpTrapToken(ctx context.Context, username string) {
	if s.db == nil {
		return
	}
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	_, _ = s.db.ExecContext(ctx, `DELETE FROM sf_snmp_trap_tokens WHERE username=$1`, username)
}

func (s *Service) putSnmpTrapToken(ctx context.Context, username, community string) error {
	if s.db == nil {
		return errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	if s.box == nil {
		return errs.B().Code(errs.Unavailable).Msg("encryption unavailable").Err()
	}
	username = strings.ToLower(strings.TrimSpace(username))
	community = strings.TrimSpace(community)
	if username == "" || community == "" {
		return errs.B().Code(errs.InvalidArgument).Msg("username and community are required").Err()
	}
	enc, err := s.box.encrypt(community)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	_, err = s.db.ExecContext(ctx, `INSERT INTO sf_snmp_trap_tokens (username, community, updated_at)
VALUES ($1,$2,now())
ON CONFLICT (username) DO UPDATE SET community=excluded.community, updated_at=now()`, username, enc)
	return err
}

func generateCommunity(username string) (string, error) {
	username = strings.ToLower(strings.TrimSpace(username))
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "sf-" + username + "-" + hex.EncodeToString(b), nil
}

type SnmpTrapTokenResponse struct {
	Community    string `json:"community"`
	ListenHost   string `json:"listenHost"`
	ListenPort   int    `json:"listenPort"`
	UpdatedAtUTC string `json:"updatedAtUtc,omitempty"`
}

// GetSnmpTrapToken returns the per-user SNMPv2c community string used for trap routing.
//
//encore:api auth method=GET path=/api/snmp/traps/token
func (s *Service) GetSnmpTrapToken(ctx context.Context) (*SnmpTrapTokenResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	rec, err := s.getSnmpTrapToken(ctx, user.Username)
	if err != nil {
		rlog.Error("failed to load snmp token", "username", user.Username, "error", err)
		return nil, errs.B().Code(errs.Internal).Msg("failed to load snmp token").Err()
	}
	if rec == nil || rec.Community == "" {
		comm, err := generateCommunity(user.Username)
		if err != nil {
			return nil, errs.B().Code(errs.Internal).Msg("failed to generate community").Err()
		}
		if err := s.putSnmpTrapToken(ctx, user.Username, comm); err != nil {
			return nil, errs.B().Code(errs.Internal).Msg("failed to store community").Err()
		}
		rec = &snmpTrapTokenRecord{Community: comm, UpdatedAt: time.Now().UTC()}
	}
	host := strings.TrimSpace(s.cfg.PublicURL)
	host = strings.TrimPrefix(host, "https://")
	host = strings.TrimPrefix(host, "http://")
	host = strings.TrimSuffix(host, "/")
	return &SnmpTrapTokenResponse{
		Community:    rec.Community,
		ListenHost:   host,
		ListenPort:   162,
		UpdatedAtUTC: rec.UpdatedAt.UTC().Format(time.RFC3339),
	}, nil
}

// RotateSnmpTrapToken rotates the per-user community string.
//
//encore:api auth method=POST path=/api/snmp/traps/token/rotate
func (s *Service) RotateSnmpTrapToken(ctx context.Context) (*SnmpTrapTokenResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	comm, err := generateCommunity(user.Username)
	if err != nil {
		return nil, errs.B().Code(errs.Internal).Msg("failed to generate community").Err()
	}
	if err := s.putSnmpTrapToken(ctx, user.Username, comm); err != nil {
		return nil, errs.B().Code(errs.Internal).Msg("failed to store community").Err()
	}
	host := strings.TrimSpace(s.cfg.PublicURL)
	host = strings.TrimPrefix(host, "https://")
	host = strings.TrimPrefix(host, "http://")
	host = strings.TrimSuffix(host, "/")
	return &SnmpTrapTokenResponse{
		Community:    comm,
		ListenHost:   host,
		ListenPort:   162,
		UpdatedAtUTC: time.Now().UTC().Format(time.RFC3339),
	}, nil
}

type SnmpTrapEvent struct {
	ID         int64     `json:"id"`
	ReceivedAt time.Time `json:"receivedAt"`
	SourceIP   string    `json:"sourceIp,omitempty"`
	OID        string    `json:"oid,omitempty"`
	VarsJSON   string    `json:"varsJson,omitempty"`
}

type SnmpTrapEventsParams struct {
	Limit    string `query:"limit" encore:"optional"`
	BeforeID string `query:"before_id" encore:"optional"`
}

type SnmpTrapEventsResponse struct {
	Events []SnmpTrapEvent `json:"events"`
}

// ListSnmpTrapEvents returns the current user's trap inbox.
//
//encore:api auth method=GET path=/api/snmp/traps/events
func (s *Service) ListSnmpTrapEvents(ctx context.Context, params *SnmpTrapEventsParams) (*SnmpTrapEventsResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("snmp store unavailable").Err()
	}
	limit := int64(200)
	if params != nil && strings.TrimSpace(params.Limit) != "" {
		if v, err := strconv.ParseInt(strings.TrimSpace(params.Limit), 10, 64); err == nil && v > 0 && v <= 1000 {
			limit = v
		}
	}
	var beforeID *int64
	if params != nil && strings.TrimSpace(params.BeforeID) != "" {
		if v, err := strconv.ParseInt(strings.TrimSpace(params.BeforeID), 10, 64); err == nil && v > 0 {
			beforeID = &v
		}
	}

	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	query := `SELECT id, received_at, COALESCE(source_ip::text,''), COALESCE(oid,''), COALESCE(vars_json,'') FROM sf_snmp_trap_events WHERE username=$1`
	args := []any{strings.ToLower(user.Username)}
	if beforeID != nil {
		query += ` AND id < $2`
		args = append(args, *beforeID)
	}
	query += ` ORDER BY id DESC LIMIT ` + strconv.FormatInt(limit, 10)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, errs.B().Code(errs.Internal).Msg("failed to query traps").Err()
	}
	defer rows.Close()

	out := make([]SnmpTrapEvent, 0, limit)
	for rows.Next() {
		var ev SnmpTrapEvent
		var src, oid, vars string
		if err := rows.Scan(&ev.ID, &ev.ReceivedAt, &src, &oid, &vars); err != nil {
			return nil, errs.B().Code(errs.Internal).Msg("failed to read trap").Err()
		}
		ev.SourceIP = strings.TrimSpace(src)
		ev.OID = strings.TrimSpace(oid)
		ev.VarsJSON = vars
		out = append(out, ev)
	}
	if err := rows.Err(); err != nil {
		return nil, errs.B().Code(errs.Internal).Msg("failed to read traps").Err()
	}
	return &SnmpTrapEventsResponse{Events: out}, nil
}
