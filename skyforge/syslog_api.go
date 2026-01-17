package skyforge

import (
	"context"
	"database/sql"
	"net"
	"strconv"
	"strings"
	"time"

	"encore.dev/beta/errs"
	"encore.dev/rlog"
)

type SyslogEvent struct {
	ID         int64     `json:"id"`
	ReceivedAt time.Time `json:"receivedAt"`
	SourceIP   string    `json:"sourceIp"`
	Hostname   string    `json:"hostname,omitempty"`
	AppName    string    `json:"appName,omitempty"`
	Facility   *int      `json:"facility,omitempty"`
	Severity   *int      `json:"severity,omitempty"`
	Message    string    `json:"message,omitempty"`
	Owner      string    `json:"owner,omitempty"`
	RouteCIDR  string    `json:"routeCidr,omitempty"`
}

type SyslogEventsParams struct {
	Limit      string `query:"limit" encore:"optional"`
	BeforeID   string `query:"before_id" encore:"optional"`
	SourceIP   string `query:"source_ip" encore:"optional"`
	Unassigned string `query:"unassigned" encore:"optional"`
}

type SyslogEventsResponse struct {
	Events []SyslogEvent `json:"events"`
}

// ListSyslogEvents returns the syslog inbox for the current user.
//
// By default it returns only events mapped to the current user via `sf_syslog_routes`.
// Admins can request unassigned events to help claim sources.
//
//encore:api auth method=GET path=/api/syslog/events
func (s *Service) ListSyslogEvents(ctx context.Context, params *SyslogEventsParams) (*SyslogEventsResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("syslog store unavailable").Err()
	}
	limit := parseSyslogLimit(params)
	beforeID := parseOptionalInt64(params.GetBeforeID())
	sourceIP := strings.TrimSpace(params.GetSourceIP())
	unassigned := parseOptionalBool(params.GetUnassigned())

	if sourceIP != "" && net.ParseIP(sourceIP) == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid source_ip").Err()
	}

	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	query := `
SELECT
  e.id,
  e.received_at,
  e.source_ip::text,
  COALESCE(e.hostname, ''),
  COALESCE(e.app_name, ''),
  e.facility,
  e.severity,
  COALESCE(e.message, ''),
  COALESCE(r.owner_username, ''),
  COALESCE(r.source_cidr::text, '')
FROM sf_syslog_events e
LEFT JOIN LATERAL (
  SELECT owner_username, source_cidr
  FROM sf_syslog_routes
  WHERE e.source_ip <<= source_cidr
  ORDER BY masklen(source_cidr) DESC
  LIMIT 1
) r ON TRUE
WHERE 1=1
`
	args := make([]any, 0, 8)
	argN := 0
	addArg := func(v any) string {
		argN++
		args = append(args, v)
		return "$" + strconv.Itoa(argN)
	}

	if beforeID != nil {
		query += " AND e.id < " + addArg(*beforeID) + "\n"
	}
	if sourceIP != "" {
		query += " AND e.source_ip = " + addArg(sourceIP) + "::inet\n"
	}

	if user.IsAdmin && user.SelectedRole == "ADMIN" && unassigned {
		query += " AND r.owner_username IS NULL\n"
	} else {
		// Default user view: only their mapped sources.
		query += " AND r.owner_username = " + addArg(user.Username) + "\n"
	}

	query += " ORDER BY e.id DESC LIMIT " + addArg(limit)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		rlog.Error("failed to query syslog events", "username", user.Username, "error", err)
		return nil, errs.B().Code(errs.Internal).Msg("failed to query syslog events").Err()
	}
	defer rows.Close()

	out := make([]SyslogEvent, 0, limit)
	for rows.Next() {
		var ev SyslogEvent
		var facility sql.NullInt64
		var severity sql.NullInt64
		var hostname, appName, message, owner, cidr string
		if err := rows.Scan(&ev.ID, &ev.ReceivedAt, &ev.SourceIP, &hostname, &appName, &facility, &severity, &message, &owner, &cidr); err != nil {
			return nil, errs.B().Code(errs.Internal).Msg("failed to read syslog event").Err()
		}
		ev.Hostname = strings.TrimSpace(hostname)
		ev.AppName = strings.TrimSpace(appName)
		ev.Message = strings.TrimSpace(message)
		if facility.Valid {
			v := int(facility.Int64)
			ev.Facility = &v
		}
		if severity.Valid {
			v := int(severity.Int64)
			ev.Severity = &v
		}
		owner = strings.TrimSpace(owner)
		cidr = strings.TrimSpace(cidr)
		if owner != "" {
			ev.Owner = owner
		}
		if cidr != "" {
			ev.RouteCIDR = cidr
		}
		out = append(out, ev)
	}
	if err := rows.Err(); err != nil {
		return nil, errs.B().Code(errs.Internal).Msg("failed to read syslog events").Err()
	}
	return &SyslogEventsResponse{Events: out}, nil
}

type SyslogRoute struct {
	SourceCIDR string    `json:"sourceCidr"`
	Owner      string    `json:"owner"`
	Label      string    `json:"label,omitempty"`
	UpdatedAt  time.Time `json:"updatedAt"`
}

type SyslogRoutesResponse struct {
	Routes []SyslogRoute `json:"routes"`
}

// ListSyslogRoutes lists configured source->user mappings (admin only).
//
//encore:api auth method=GET path=/api/syslog/routes tag:admin
func (s *Service) ListSyslogRoutes(ctx context.Context) (*SyslogRoutesResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if !user.IsAdmin || user.SelectedRole != "ADMIN" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("admin required").Err()
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("syslog store unavailable").Err()
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	rows, err := s.db.QueryContext(ctx, `SELECT source_cidr::text, owner_username, COALESCE(label,''), updated_at FROM sf_syslog_routes ORDER BY updated_at DESC`)
	if err != nil {
		return nil, errs.B().Code(errs.Internal).Msg("failed to list syslog routes").Err()
	}
	defer rows.Close()

	out := make([]SyslogRoute, 0, 64)
	for rows.Next() {
		var r SyslogRoute
		var label string
		if err := rows.Scan(&r.SourceCIDR, &r.Owner, &label, &r.UpdatedAt); err != nil {
			return nil, errs.B().Code(errs.Internal).Msg("failed to read syslog route").Err()
		}
		r.Label = strings.TrimSpace(label)
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, errs.B().Code(errs.Internal).Msg("failed to list syslog routes").Err()
	}
	return &SyslogRoutesResponse{Routes: out}, nil
}

type SyslogRouteUpsertParams struct {
	SourceCIDR string `json:"sourceCidr"`
	Owner      string `json:"owner"`
	Label      string `json:"label,omitempty"`
}

// UpsertSyslogRoute creates/updates a syslog route (admin only).
//
//encore:api auth method=PUT path=/api/syslog/routes tag:admin
func (s *Service) UpsertSyslogRoute(ctx context.Context, params *SyslogRouteUpsertParams) (*SyslogRoute, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if !user.IsAdmin || user.SelectedRole != "ADMIN" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("admin required").Err()
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("syslog store unavailable").Err()
	}
	if params == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid payload").Err()
	}
	source := strings.TrimSpace(params.SourceCIDR)
	owner := strings.TrimSpace(params.Owner)
	if source == "" || owner == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("sourceCidr and owner are required").Err()
	}
	if _, _, err := net.ParseCIDR(source); err != nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid sourceCidr").Err()
	}

	prevOwner, _ := lookupSyslogOwnerForCIDR(ctx, s.db, source)

	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	_, err = s.db.ExecContext(ctx, `
INSERT INTO sf_syslog_routes (source_cidr, owner_username, label, updated_at)
VALUES ($1::cidr, $2, $3, now())
ON CONFLICT (source_cidr)
DO UPDATE SET owner_username = excluded.owner_username, label = excluded.label, updated_at = now()
`, source, owner, strings.TrimSpace(params.Label))
	if err != nil {
		return nil, errs.B().Code(errs.Internal).Msg("failed to upsert syslog route").Err()
	}

	var label string
	var updated time.Time
	if err := s.db.QueryRowContext(ctx, `SELECT COALESCE(label,''), updated_at FROM sf_syslog_routes WHERE source_cidr=$1::cidr`, source).Scan(&label, &updated); err != nil {
		return nil, errs.B().Code(errs.Internal).Msg("failed to read syslog route").Err()
	}
	out := &SyslogRoute{SourceCIDR: source, Owner: owner, Label: strings.TrimSpace(label), UpdatedAt: updated}

	// Best-effort: routes change inbox membership; notify both old and new owners.
	_ = notifySyslogUpdatePG(ctx, s.db, owner)
	if prevOwner != "" && !strings.EqualFold(prevOwner, owner) {
		_ = notifySyslogUpdatePG(ctx, s.db, prevOwner)
	}
	return out, nil
}

type SyslogRouteDeleteParams struct {
	SourceCIDR string `query:"sourceCidr"`
}

// DeleteSyslogRoute deletes a syslog route (admin only).
//
//encore:api auth method=DELETE path=/api/syslog/routes tag:admin
func (s *Service) DeleteSyslogRoute(ctx context.Context, params *SyslogRouteDeleteParams) error {
	user, err := requireAuthUser()
	if err != nil {
		return err
	}
	if !user.IsAdmin || user.SelectedRole != "ADMIN" {
		return errs.B().Code(errs.PermissionDenied).Msg("admin required").Err()
	}
	if s.db == nil {
		return errs.B().Code(errs.Unavailable).Msg("syslog store unavailable").Err()
	}
	source := strings.TrimSpace(params.SourceCIDR)
	if source == "" {
		return errs.B().Code(errs.InvalidArgument).Msg("sourceCidr is required").Err()
	}
	if _, _, err := net.ParseCIDR(source); err != nil {
		return errs.B().Code(errs.InvalidArgument).Msg("invalid sourceCidr").Err()
	}
	prevOwner, _ := lookupSyslogOwnerForCIDR(ctx, s.db, source)
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	_, err = s.db.ExecContext(ctx, `DELETE FROM sf_syslog_routes WHERE source_cidr=$1::cidr`, source)
	if err != nil {
		return errs.B().Code(errs.Internal).Msg("failed to delete syslog route").Err()
	}
	if prevOwner != "" {
		_ = notifySyslogUpdatePG(ctx, s.db, prevOwner)
	}
	return nil
}

func (p *SyslogEventsParams) GetBeforeID() string {
	if p == nil {
		return ""
	}
	return p.BeforeID
}

func (p *SyslogEventsParams) GetSourceIP() string {
	if p == nil {
		return ""
	}
	return p.SourceIP
}

func (p *SyslogEventsParams) GetUnassigned() string {
	if p == nil {
		return ""
	}
	return p.Unassigned
}

func parseSyslogLimit(params *SyslogEventsParams) int64 {
	if params == nil {
		return 200
	}
	raw := strings.TrimSpace(params.Limit)
	if raw == "" {
		return 200
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || v <= 0 {
		return 200
	}
	if v > 1000 {
		return 1000
	}
	return v
}

func parseOptionalInt64(raw string) *int64 {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return nil
	}
	return &v
}

func parseOptionalBool(raw string) bool {
	raw = strings.TrimSpace(strings.ToLower(raw))
	return raw == "1" || raw == "true" || raw == "yes" || raw == "on"
}

func lookupSyslogOwnerForCIDR(ctx context.Context, db *sql.DB, sourceCIDR string) (string, error) {
	if db == nil {
		return "", nil
	}
	sourceCIDR = strings.TrimSpace(sourceCIDR)
	if sourceCIDR == "" {
		return "", nil
	}
	ctxReq, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()
	var owner string
	if err := db.QueryRowContext(ctxReq, `SELECT owner_username FROM sf_syslog_routes WHERE source_cidr=$1::cidr`, sourceCIDR).Scan(&owner); err != nil {
		if err == sql.ErrNoRows {
			return "", nil
		}
		return "", err
	}
	return strings.TrimSpace(owner), nil
}

func lookupSyslogOwnerForIP(ctx context.Context, db *sql.DB, sourceIP string) (string, error) {
	if db == nil {
		return "", nil
	}
	sourceIP = strings.TrimSpace(sourceIP)
	if sourceIP == "" {
		return "", nil
	}
	ctxReq, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()
	var owner sql.NullString
	if err := db.QueryRowContext(ctxReq, `
SELECT owner_username
FROM sf_syslog_routes
WHERE $1::inet <<= source_cidr
ORDER BY masklen(source_cidr) DESC
LIMIT 1
`, sourceIP).Scan(&owner); err != nil {
		if err == sql.ErrNoRows {
			return "", nil
		}
		return "", err
	}
	return strings.TrimSpace(owner.String), nil
}
