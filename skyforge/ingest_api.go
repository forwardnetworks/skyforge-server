package skyforge

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"net"
	"strings"
	"time"

	"encore.dev/beta/errs"
)

type InternalIngestAuth struct {
	Token string `header:"X-Skyforge-Internal-Token"`
}

func (s *Service) requireInternalIngest(token string) error {
	if strings.TrimSpace(s.cfg.InternalToken) == "" {
		return errs.B().Code(errs.NotFound).Msg("not found").Err()
	}
	token = strings.TrimSpace(token)
	if token == "" || subtle.ConstantTimeCompare([]byte(token), []byte(s.cfg.InternalToken)) != 1 {
		return errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	if s.db == nil {
		return errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	return nil
}

type IngestSyslogParams struct {
	Token string `header:"X-Skyforge-Internal-Token" json:"-"`

	SourceIP   string `json:"source_ip"`
	Hostname   string `json:"hostname,omitempty"`
	AppName    string `json:"app_name,omitempty"`
	ProcID     string `json:"proc_id,omitempty"`
	MsgID      string `json:"msg_id,omitempty"`
	Facility   *int   `json:"facility,omitempty"`
	Severity   *int   `json:"severity,omitempty"`
	Message    string `json:"message,omitempty"`
	Raw        string `json:"raw,omitempty"`
	ReceivedAt string `json:"received_at,omitempty"`
}

// IngestSyslog accepts syslog events from in-cluster collectors (Vector/Fluent Bit/etc).
//
// This endpoint is intentionally unauthenticated (SSO) and guarded by an internal token header.
//
//encore:api public method=POST path=/ingest/syslog
func (s *Service) IngestSyslog(ctx context.Context, params *IngestSyslogParams) error {
	if err := s.requireInternalIngest(params.Token); err != nil {
		return err
	}
	if params == nil {
		return errs.B().Code(errs.InvalidArgument).Msg("invalid payload").Err()
	}
	sourceIP := strings.TrimSpace(params.SourceIP)
	if sourceIP == "" || net.ParseIP(sourceIP) == nil {
		return errs.B().Code(errs.InvalidArgument).Msg("invalid source_ip").Err()
	}

	receivedAt := time.Now().UTC()
	if raw := strings.TrimSpace(params.ReceivedAt); raw != "" {
		if t, err := time.Parse(time.RFC3339Nano, raw); err == nil {
			receivedAt = t.UTC()
		}
	}

	rawLine := strings.TrimSpace(params.Raw)
	if rawLine == "" {
		rawLine = strings.TrimSpace(params.Message)
	}
	if rawLine == "" {
		rawLine = `{"error":"empty syslog event"}`
	}

	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	_, err := s.db.ExecContext(ctx, `
INSERT INTO sf_syslog_events (
  received_at,
  source_ip,
  hostname,
  app_name,
  proc_id,
  msg_id,
  facility,
  severity,
  message,
  raw
)
VALUES ($1, $2::inet, NULLIF($3,''), NULLIF($4,''), NULLIF($5,''), NULLIF($6,''), $7, $8, NULLIF($9,''), $10)
`, receivedAt, sourceIP, strings.TrimSpace(params.Hostname), strings.TrimSpace(params.AppName), strings.TrimSpace(params.ProcID), strings.TrimSpace(params.MsgID), nullableInt(params.Facility), nullableInt(params.Severity), strings.TrimSpace(params.Message), rawLine)
	if err != nil {
		return errs.B().Code(errs.Internal).Msg("failed to store syslog event").Err()
	}

	// Best-effort: notify the mapped owner (if any) so UIs can update via SSE.
	owner := ""
	if v, err := lookupSyslogOwnerForIP(ctx, s.db, sourceIP); err == nil && strings.TrimSpace(v) != "" {
		owner = strings.TrimSpace(v)
		_ = notifySyslogUpdatePG(ctx, s.db, owner)
	}

	s.indexElasticAsync(owner, "syslog", receivedAt, map[string]any{
		"received_at": receivedAt.Format(time.RFC3339Nano),
		"owner":       owner,
		"source_ip":   sourceIP,
		"hostname":    strings.TrimSpace(params.Hostname),
		"app_name":    strings.TrimSpace(params.AppName),
		"proc_id":     strings.TrimSpace(params.ProcID),
		"msg_id":      strings.TrimSpace(params.MsgID),
		"facility":    params.Facility,
		"severity":    params.Severity,
		"message":     strings.TrimSpace(params.Message),
		"raw":         rawLine,
	})
	return nil
}

func nullableInt(v *int) sql.NullInt64 {
	if v == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: int64(*v), Valid: true}
}

type IngestTelegrafMetricParams struct {
	Token string `header:"X-Skyforge-Internal-Token" json:"-"`

	Name      string                     `json:"name"`
	Tags      map[string]string          `json:"tags"`
	Fields    map[string]json.RawMessage `json:"fields"`
	Timestamp *int64                     `json:"timestamp,omitempty"`
}

// IngestSNMPTrap accepts SNMP trap events from in-cluster collectors (Telegraf).
//
// Expected payload is Telegraf JSON serializer output for `inputs.snmp_trap`.
//
//encore:api public method=POST path=/ingest/snmp/trap
func (s *Service) IngestSNMPTrap(ctx context.Context, params *IngestTelegrafMetricParams) error {
	if err := s.requireInternalIngest(params.Token); err != nil {
		return err
	}
	return errs.B().Code(errs.FailedPrecondition).Msg("SNMP trap ingestion is disabled; use SNMPv3 polling-based collection").Err()

	if params == nil {
		return errs.B().Code(errs.InvalidArgument).Msg("invalid payload").Err()
	}

	sourceIP := strings.TrimSpace(firstNonEmptyMetric(
		getTag(params.Tags, "source"),
		getTag(params.Tags, "source_ip"),
		getTag(params.Tags, "src"),
	))
	if sourceIP != "" && net.ParseIP(sourceIP) == nil {
		sourceIP = ""
	}
	community := strings.TrimSpace(firstNonEmptyMetric(
		getTag(params.Tags, "community"),
		getTag(params.Tags, "snmp_community"),
	))
	oid := strings.TrimSpace(firstNonEmptyMetric(
		getField(params.Fields, "oid"),
		getField(params.Fields, "snmp_oid"),
	))

	varsJSON, _ := json.Marshal(params.Fields)

	username := ""
	if community != "" {
		u, err := s.lookupSnmpTrapOwner(ctx, community)
		if err != nil {
			return err
		}
		username = u
	}

	receivedAt := time.Now().UTC()
	if params.Timestamp != nil && *params.Timestamp > 0 {
		receivedAt = time.Unix(*params.Timestamp, 0).UTC()
	}

	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	var source sql.NullString
	if sourceIP != "" {
		source = sql.NullString{String: sourceIP, Valid: true}
	}
	var user sql.NullString
	if strings.TrimSpace(username) != "" {
		user = sql.NullString{String: username, Valid: true}
	}
	var comm sql.NullString
	if community != "" {
		comm = sql.NullString{String: community, Valid: true}
	}
	var oidVal sql.NullString
	if oid != "" {
		oidVal = sql.NullString{String: oid, Valid: true}
	}

	_, err := s.db.ExecContext(ctx, `
INSERT INTO sf_snmp_trap_events (
  received_at,
  username,
  source_ip,
  community,
  oid,
  vars_json
)
VALUES ($1, NULLIF($2,''), NULLIF($3,'')::inet, NULLIF($4,''), NULLIF($5,''), $6)
`, receivedAt, user.String, source.String, comm.String, oidVal.String, string(varsJSON))
	if err != nil {
		return errs.B().Code(errs.Internal).Msg("failed to store snmp trap").Err()
	}

	// Best-effort: notify the mapped owner (if any) so UIs can update via SSE.
	if strings.TrimSpace(username) != "" {
		_ = notifySnmpUpdatePG(ctx, s.db, username)
	}

	s.indexElasticAsync(username, "snmp-trap", receivedAt, map[string]any{
		"received_at": receivedAt.Format(time.RFC3339Nano),
		"username":    username,
		"source_ip":   sourceIP,
		"community":   community,
		"oid":         oid,
		"metric_name": strings.TrimSpace(params.Name),
		"tags":        params.Tags,
		"fields":      json.RawMessage(varsJSON),
	})
	return nil
}

// IngestNodeMetric accepts host/node metrics from in-cluster collectors (Telegraf).
//
// This is used to build a lightweight "live node metrics" view without deploying a full monitoring stack.
// Data is stored as a short-lived snapshot in Redis.
//
//encore:api public method=POST path=/ingest/metrics/node
func (s *Service) IngestNodeMetric(ctx context.Context, params *IngestTelegrafMetricParams) error {
	if err := s.requireInternalIngest(params.Token); err != nil {
		return err
	}
	if params == nil {
		return errs.B().Code(errs.InvalidArgument).Msg("invalid payload").Err()
	}

	node := strings.TrimSpace(firstNonEmptyMetric(
		getTag(params.Tags, "node"),
		getTag(params.Tags, "nodename"),
		getTag(params.Tags, "host"),
	))
	if node == "" {
		return errs.B().Code(errs.InvalidArgument).Msg("missing node/host tag").Err()
	}
	name := strings.TrimSpace(params.Name)
	if name == "" {
		return errs.B().Code(errs.InvalidArgument).Msg("missing metric name").Err()
	}

	clean := IngestTelegrafMetricParams{
		Name:      params.Name,
		Tags:      params.Tags,
		Fields:    params.Fields,
		Timestamp: params.Timestamp,
	}
	raw, err := json.Marshal(&clean)
	if err != nil {
		return errs.B().Code(errs.InvalidArgument).Msg("invalid payload").Err()
	}

	if s.db == nil {
		return errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	ctxReq, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := upsertNodeMetricSnapshot(ctxReq, s.db, node, name, time.Now(), string(raw)); err != nil {
		return errs.B().Code(errs.Internal).Msg("failed to store node metric").Err()
	}
	return nil
}

func getTag(tags map[string]string, key string) string {
	if tags == nil {
		return ""
	}
	return strings.TrimSpace(tags[key])
}

func getField(fields map[string]json.RawMessage, key string) string {
	if fields == nil {
		return ""
	}
	raw, ok := fields[key]
	if !ok {
		return ""
	}
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return strings.TrimSpace(s)
	}
	return strings.TrimSpace(string(raw))
}

func firstNonEmptyMetric(vals ...string) string {
	for _, v := range vals {
		v = strings.TrimSpace(v)
		if v != "" {
			return v
		}
	}
	return ""
}

func (s *Service) lookupSnmpTrapOwner(ctx context.Context, community string) (string, error) {
	if strings.TrimSpace(community) == "" {
		return "", nil
	}
	if s.box == nil {
		return "", errs.B().Code(errs.Unavailable).Msg("encryption unavailable").Err()
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	rows, err := s.db.QueryContext(ctx, `SELECT username, community FROM sf_snmp_trap_tokens`)
	if err != nil {
		return "", errs.B().Code(errs.Internal).Msg("failed to read snmp trap tokens").Err()
	}
	defer rows.Close()

	for rows.Next() {
		var username string
		var enc string
		if err := rows.Scan(&username, &enc); err != nil {
			return "", errs.B().Code(errs.Internal).Msg("failed to read snmp trap token").Err()
		}
		dec, err := s.box.decrypt(enc)
		if err != nil {
			continue
		}
		if strings.TrimSpace(dec) == community {
			return strings.TrimSpace(username), nil
		}
	}
	if err := rows.Err(); err != nil {
		return "", errs.B().Code(errs.Internal).Msg("failed to scan snmp trap tokens").Err()
	}
	return "", nil
}
