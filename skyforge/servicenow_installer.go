package skyforge

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type serviceNowInstallerConfig struct {
	InstanceURL     string
	AdminUsername   string
	AdminPassword   string
	ForwardBaseURL  string
	ForwardUsername string
	ForwardPassword string
	Assets          servicenowDemoAssets
}

type serviceNowInstaller struct {
	cfg    serviceNowInstallerConfig
	client *http.Client
}

type serviceNowDictField struct {
	Table        string
	Element      string
	Label        string
	InternalType string
	MaxLength    int
	ChoiceValues []struct {
		Value string
		Label string
	}
	Reference string
}

func newServiceNowInstaller(cfg serviceNowInstallerConfig) *serviceNowInstaller {
	return &serviceNowInstaller{
		cfg: cfg,
		client: &http.Client{
			Timeout: 20 * time.Second,
		},
	}
}

func (i *serviceNowInstaller) Install(ctx context.Context) error {
	if i == nil {
		return fmt.Errorf("installer unavailable")
	}
	if strings.TrimSpace(i.cfg.InstanceURL) == "" {
		return fmt.Errorf("instance url is required")
	}
	if strings.TrimSpace(i.cfg.AdminUsername) == "" || strings.TrimSpace(i.cfg.AdminPassword) == "" {
		return fmt.Errorf("servicenow admin credentials are required")
	}
	if strings.TrimSpace(i.cfg.ForwardUsername) == "" || strings.TrimSpace(i.cfg.ForwardPassword) == "" {
		return fmt.Errorf("forward credentials are required")
	}
	if strings.TrimSpace(i.cfg.ForwardBaseURL) == "" {
		i.cfg.ForwardBaseURL = defaultServiceNowForwardBaseURL
	}

	// Best-effort: install all script artifacts + portal widget + REST message + basic auth credential.
	// The schema (tables/fields) remains a manual step for now due to ServiceNow platform complexity.
	if err := i.ensureProperties(ctx); err != nil {
		return err
	}
	if err := i.ensureSchema(ctx); err != nil {
		return err
	}
	credID, err := i.ensureForwardBasicAuthCredential(ctx)
	if err != nil {
		// Some ServiceNow instances restrict credential tables; we can still proceed because
		// ForwardClient also supports explicit rm.setBasicAuth() from sys_properties.
		credID = ""
	}
	restMsgID, err := i.ensureForwardRestMessage(ctx, credID)
	if err != nil {
		return err
	}
	if err := i.ensureForwardRestMethods(ctx, restMsgID); err != nil {
		return err
	}
	if err := i.ensureScriptIncludes(ctx); err != nil {
		return err
	}
	if err := i.ensureEventAndScriptAction(ctx); err != nil {
		return err
	}
	if err := i.ensureServicePortalWidget(ctx); err != nil {
		return err
	}

	// Smoke test: invoke List Networks method via RESTMessage record execution is not directly available,
	// but we can validate the REST message record exists and the credential is present.
	return nil
}

func (i *serviceNowInstaller) ensureSchema(ctx context.Context) error {
	// Tables:
	// - x_fwd_demo_connectivity_ticket (extends task)
	// - x_fwd_demo_connectivity_hop

	taskObj, err := i.findByField(ctx, "sys_db_object", "name", "task")
	if err != nil {
		return fmt.Errorf("schema lookup task table: %w", err)
	}
	taskSysID := ""
	if taskObj != nil {
		taskSysID, _ = taskObj["sys_id"].(string)
	}
	if strings.TrimSpace(taskSysID) == "" {
		return fmt.Errorf("schema: could not resolve sys_db_object for task")
	}

	if err := i.upsertTableByKey(ctx, "sys_db_object", "name", "x_fwd_demo_connectivity_ticket", map[string]any{
		"name":        "x_fwd_demo_connectivity_ticket",
		"label":       "Connectivity Ticket",
		"super_class": taskSysID,
	}); err != nil {
		return fmt.Errorf("schema: create ticket table: %w", err)
	}
	if err := i.upsertTableByKey(ctx, "sys_db_object", "name", "x_fwd_demo_connectivity_hop", map[string]any{
		"name":  "x_fwd_demo_connectivity_hop",
		"label": "Connectivity Hop",
	}); err != nil {
		return fmt.Errorf("schema: create hop table: %w", err)
	}

	fields := []serviceNowDictField{
		// Ticket flow input
		{Table: "x_fwd_demo_connectivity_ticket", Element: "u_src_ip", Label: "Source IP", InternalType: "string", MaxLength: 45},
		{Table: "x_fwd_demo_connectivity_ticket", Element: "u_dst_ip", Label: "Destination IP", InternalType: "string", MaxLength: 45},
		{Table: "x_fwd_demo_connectivity_ticket", Element: "u_protocol", Label: "Protocol", InternalType: "choice", ChoiceValues: []struct {
			Value string
			Label string
		}{{Value: "TCP", Label: "TCP"}, {Value: "UDP", Label: "UDP"}}},
		{Table: "x_fwd_demo_connectivity_ticket", Element: "u_dst_port", Label: "Destination Port", InternalType: "integer"},

		// Forward selection
		{Table: "x_fwd_demo_connectivity_ticket", Element: "u_forward_network_id", Label: "Forward Network ID", InternalType: "string"},
		{Table: "x_fwd_demo_connectivity_ticket", Element: "u_forward_snapshot_id", Label: "Forward Snapshot ID", InternalType: "string"},

		// Analysis results
		{Table: "x_fwd_demo_connectivity_ticket", Element: "u_allowed", Label: "Allowed", InternalType: "boolean"},
		{Table: "x_fwd_demo_connectivity_ticket", Element: "u_block_category", Label: "Block Category", InternalType: "choice", ChoiceValues: []struct {
			Value string
			Label string
		}{{Value: "network", Label: "network"}, {Value: "security", Label: "security"}, {Value: "unknown", Label: "unknown"}}},
		{Table: "x_fwd_demo_connectivity_ticket", Element: "u_block_device", Label: "Block Device", InternalType: "string"},
		{Table: "x_fwd_demo_connectivity_ticket", Element: "u_block_interface", Label: "Block Interface", InternalType: "string"},
		{Table: "x_fwd_demo_connectivity_ticket", Element: "u_block_rule", Label: "Block Rule", InternalType: "string"},
		{Table: "x_fwd_demo_connectivity_ticket", Element: "u_block_reason", Label: "Block Reason", InternalType: "string", MaxLength: 4000},
		{Table: "x_fwd_demo_connectivity_ticket", Element: "u_forward_query_url", Label: "Forward Query URL", InternalType: "string"},
		{Table: "x_fwd_demo_connectivity_ticket", Element: "u_raw_excerpt", Label: "Raw Excerpt", InternalType: "string", MaxLength: 4000},

		// Analysis state
		{Table: "x_fwd_demo_connectivity_ticket", Element: "u_analysis_status", Label: "Analysis Status", InternalType: "choice", ChoiceValues: []struct {
			Value string
			Label string
		}{{Value: "not_run", Label: "not_run"}, {Value: "running", Label: "running"}, {Value: "complete", Label: "complete"}, {Value: "error", Label: "error"}}},
		{Table: "x_fwd_demo_connectivity_ticket", Element: "u_analysis_error", Label: "Analysis Error", InternalType: "string", MaxLength: 4000},

		// Hop table
		{Table: "x_fwd_demo_connectivity_hop", Element: "u_ticket", Label: "Ticket", InternalType: "reference", Reference: "x_fwd_demo_connectivity_ticket"},
		{Table: "x_fwd_demo_connectivity_hop", Element: "u_hop_index", Label: "Hop Index", InternalType: "integer"},
		{Table: "x_fwd_demo_connectivity_hop", Element: "u_device", Label: "Device", InternalType: "string"},
		{Table: "x_fwd_demo_connectivity_hop", Element: "u_ingress", Label: "Ingress", InternalType: "string"},
		{Table: "x_fwd_demo_connectivity_hop", Element: "u_egress", Label: "Egress", InternalType: "string"},
		{Table: "x_fwd_demo_connectivity_hop", Element: "u_note", Label: "Note", InternalType: "string"},
	}

	for _, f := range fields {
		if err := i.ensureDictionaryField(ctx, f); err != nil {
			return err
		}
	}
	return nil
}

func (i *serviceNowInstaller) ensureDictionaryField(ctx context.Context, f serviceNowDictField) error {
	table := strings.TrimSpace(f.Table)
	element := strings.TrimSpace(f.Element)
	if table == "" || element == "" {
		return fmt.Errorf("schema: invalid dictionary field")
	}
	query := fmt.Sprintf("name=%s^element=%s", table, element)
	existing, err := i.findByQuery(ctx, "sys_dictionary", query)
	if err != nil {
		return fmt.Errorf("schema: lookup %s.%s: %w", table, element, err)
	}
	payload := map[string]any{
		"name":          table,
		"element":       element,
		"column_label":  f.Label,
		"internal_type": f.InternalType,
	}
	if f.MaxLength > 0 {
		payload["max_length"] = f.MaxLength
	}
	if strings.TrimSpace(f.Reference) != "" {
		payload["reference"] = strings.TrimSpace(f.Reference)
	}
	if existing != nil {
		sysID, _ := existing["sys_id"].(string)
		if strings.TrimSpace(sysID) != "" {
			if err := i.updateBySysID(ctx, "sys_dictionary", sysID, payload); err != nil {
				return fmt.Errorf("schema: update %s.%s: %w", table, element, err)
			}
		}
	} else {
		if _, err := i.create(ctx, "sys_dictionary", payload); err != nil {
			return fmt.Errorf("schema: create %s.%s: %w", table, element, err)
		}
	}

	// Choices
	if strings.EqualFold(strings.TrimSpace(f.InternalType), "choice") && len(f.ChoiceValues) > 0 {
		for idx, c := range f.ChoiceValues {
			choiceQuery := fmt.Sprintf("name=%s^element=%s^value=%s", table, element, c.Value)
			ch, err := i.findByQuery(ctx, "sys_choice", choiceQuery)
			if err != nil {
				continue
			}
			chPayload := map[string]any{
				"name":    table,
				"element": element,
				"value":   c.Value,
				"label":   c.Label,
				"sequence": (idx + 1) * 10,
			}
			if ch != nil {
				sysID, _ := ch["sys_id"].(string)
				if strings.TrimSpace(sysID) != "" {
					_ = i.updateBySysID(ctx, "sys_choice", sysID, chPayload)
				}
			} else {
				_, _ = i.create(ctx, "sys_choice", chPayload)
			}
		}
	}
	return nil
}

func (i *serviceNowInstaller) ensureProperties(ctx context.Context) error {
	props := map[string]string{
		"x_fwd_demo.forward.base_url":    strings.TrimRight(i.cfg.ForwardBaseURL, "/"),
		"x_fwd_demo.forward.max_results": "1",
		"x_fwd_demo.forward.username":    strings.TrimSpace(i.cfg.ForwardUsername),
		"x_fwd_demo.forward.password":    strings.TrimSpace(i.cfg.ForwardPassword),
		"x_fwd_demo.groups.network":      "Network Team",
		"x_fwd_demo.groups.security":     "Security Team",
		"x_fwd_demo.groups.triage":       "Triage",
	}
	for name, value := range props {
		if err := i.upsertTableByKey(ctx, "sys_properties", "name", name, map[string]any{
			"name":  name,
			"value": value,
		}); err != nil {
			return fmt.Errorf("servicenow property %s: %w", name, err)
		}
	}
	return nil
}

// ensureForwardBasicAuthCredential creates a Basic Auth credential used by the Forward REST message.
// ServiceNow has multiple credential tables; this uses sys_auth_profile_basic (commonly used for Basic Auth).
func (i *serviceNowInstaller) ensureForwardBasicAuthCredential(ctx context.Context) (string, error) {
	// Name in ServiceNow credential store.
	name := "Forward Demo"
	sysID, err := i.upsertTableByKeyReturnSysID(ctx, "sys_auth_profile_basic", "name", name, map[string]any{
		"name":     name,
		"active":   true,
		"username": i.cfg.ForwardUsername,
		"password": i.cfg.ForwardPassword,
	})
	if err != nil {
		return "", fmt.Errorf("servicenow credential: %w", err)
	}
	return sysID, nil
}

func (i *serviceNowInstaller) ensureForwardRestMessage(ctx context.Context, basicAuthProfileSysID string) (string, error) {
	name := "Forward API"
	// Endpoint is overridden at runtime by ForwardClient, but keep a valid default.
	defaultEndpoint := strings.TrimRight(i.cfg.ForwardBaseURL, "/")
	if defaultEndpoint == "" {
		defaultEndpoint = defaultServiceNowForwardBaseURL
	}
	fields := map[string]any{
		"name":     name,
		"endpoint": defaultEndpoint,
		"active":   true,
	}

	// Best effort binding: these fields vary between SN versions.
	// If they are invalid, ServiceNow will reject the update; we will surface the error.
	if strings.TrimSpace(basicAuthProfileSysID) != "" {
		fields["authentication_type"] = "basic"
		fields["authentication_profile"] = basicAuthProfileSysID
	}

	sysID, err := i.upsertTableByKeyReturnSysID(ctx, "sys_rest_message", "name", name, fields)
	if err != nil {
		return "", fmt.Errorf("servicenow rest message: %w", err)
	}
	return sysID, nil
}

func (i *serviceNowInstaller) ensureForwardRestMethods(ctx context.Context, restMessageSysID string) error {
	type methodSpec struct {
		Name       string
		HTTPMethod string
		Endpoint   string
		Query      map[string]string
	}
	methods := []methodSpec{
		{Name: "List Networks", HTTPMethod: "get", Endpoint: "/networks"},
		{Name: "List Snapshots", HTTPMethod: "get", Endpoint: "/networks/${networkId}/snapshots", Query: map[string]string{"state": "PROCESSED", "limit": "50"}},
		{Name: "Path Search", HTTPMethod: "get", Endpoint: "/networks/${networkId}/paths"},
	}
	for _, m := range methods {
		sysID, err := i.upsertTableByKeyReturnSysID(ctx, "sys_rest_message_fn", "name", m.Name, map[string]any{
			"name":         m.Name,
			"rest_message": restMessageSysID,
			"http_method":  m.HTTPMethod,
			"endpoint":     m.Endpoint,
			"active":       true,
		})
		if err != nil {
			return fmt.Errorf("rest method %s: %w", m.Name, err)
		}
		for k, v := range m.Query {
			// Table name varies; use sys_rest_message_fn_param as a best guess.
			_ = i.upsertTableByKey(ctx, "sys_rest_message_fn_param", "name", k, map[string]any{
				"name":           k,
				"value":          v,
				"rest_message_fn": sysID,
				"parameter_type": "query",
			})
		}
	}
	return nil
}

func (i *serviceNowInstaller) ensureScriptIncludes(ctx context.Context) error {
	includes := []struct {
		Name   string
		Script string
	}{
		{"ForwardClient", i.cfg.Assets.ForwardClientJS},
		{"PathNormalizer", i.cfg.Assets.PathNormalizerJS},
		{"TicketAnalysis", i.cfg.Assets.TicketAnalysisJS},
	}
	for _, inc := range includes {
		if err := i.upsertTableByKey(ctx, "sys_script_include", "name", inc.Name, map[string]any{
			"name":  inc.Name,
			"active": true,
			"script": inc.Script,
		}); err != nil {
			return fmt.Errorf("script include %s: %w", inc.Name, err)
		}
	}
	return nil
}

func (i *serviceNowInstaller) ensureEventAndScriptAction(ctx context.Context) error {
	// Event registry entry
	eventName := "x_fwd_demo.analyze_ticket"
	_ = i.upsertTableByKey(ctx, "sysevent_register", "name", eventName, map[string]any{
		"name":        eventName,
		"description": "Forward demo: analyze connectivity ticket",
	})

	// Script Action bound to the event
	actionName := "AnalyzeTicket"
	if err := i.upsertTableByKey(ctx, "sys_script_action", "name", actionName, map[string]any{
		"name":        actionName,
		"active":      true,
		"event_name":  eventName,
		"script":      i.cfg.Assets.AnalyzeTicketScriptJS,
	}); err != nil {
		return fmt.Errorf("script action: %w", err)
	}
	return nil
}

func (i *serviceNowInstaller) ensureServicePortalWidget(ctx context.Context) error {
	name := "Connectivity Ticket Analyzer"
	if err := i.upsertTableByKey(ctx, "sp_widget", "name", name, map[string]any{
		"name":          name,
		"active":        true,
		"client_script": i.cfg.Assets.WidgetClientJS,
		"server_script": i.cfg.Assets.WidgetServerJS,
		"template":      i.cfg.Assets.WidgetTemplateHTML,
		"css":           i.cfg.Assets.WidgetStyleCSS,
	}); err != nil {
		return fmt.Errorf("service portal widget: %w", err)
	}
	return nil
}

func (i *serviceNowInstaller) tableURL(table string) (string, error) {
	table = strings.TrimSpace(table)
	if table == "" {
		return "", fmt.Errorf("table required")
	}
	base, err := url.Parse(strings.TrimRight(i.cfg.InstanceURL, "/"))
	if err != nil {
		return "", err
	}
	base.Path = "/api/now/table/" + table
	base.RawQuery = ""
	return base.String(), nil
}

func (i *serviceNowInstaller) upsertTableByKey(ctx context.Context, table, keyField, keyValue string, fields map[string]any) error {
	_, err := i.upsertTableByKeyReturnSysID(ctx, table, keyField, keyValue, fields)
	return err
}

func (i *serviceNowInstaller) upsertTableByKeyReturnSysID(ctx context.Context, table, keyField, keyValue string, fields map[string]any) (string, error) {
	keyField = strings.TrimSpace(keyField)
	keyValue = strings.TrimSpace(keyValue)
	if keyField == "" || keyValue == "" {
		return "", fmt.Errorf("key required")
	}

	existing, err := i.findByField(ctx, table, keyField, keyValue)
	if err != nil {
		return "", err
	}
	if existing != nil {
		sysID, _ := existing["sys_id"].(string)
		if sysID == "" {
			return "", fmt.Errorf("missing sys_id")
		}
		if err := i.updateBySysID(ctx, table, sysID, fields); err != nil {
			return "", err
		}
		return sysID, nil
	}
	sysID, err := i.create(ctx, table, fields)
	if err != nil {
		return "", err
	}
	return sysID, nil
}

func (i *serviceNowInstaller) findByField(ctx context.Context, table, field, value string) (map[string]any, error) {
	u, err := i.tableURL(table)
	if err != nil {
		return nil, err
	}
	q := url.Values{}
	q.Set("sysparm_limit", "1")
	q.Set("sysparm_query", fmt.Sprintf("%s=%s", field, value))
	u = u + "?" + q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	i.addAuth(req)
	resp, err := i.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("servicenow get %s: %s", table, strings.TrimSpace(string(body)))
	}
	var parsed struct {
		Result []map[string]any `json:"result"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, err
	}
	if len(parsed.Result) == 0 {
		return nil, nil
	}
	return parsed.Result[0], nil
}

func (i *serviceNowInstaller) findByQuery(ctx context.Context, table, query string) (map[string]any, error) {
	u, err := i.tableURL(table)
	if err != nil {
		return nil, err
	}
	q := url.Values{}
	q.Set("sysparm_limit", "1")
	q.Set("sysparm_query", query)
	u = u + "?" + q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	i.addAuth(req)
	resp, err := i.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("servicenow get %s: %s", table, strings.TrimSpace(string(body)))
	}
	var parsed struct {
		Result []map[string]any `json:"result"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, err
	}
	if len(parsed.Result) == 0 {
		return nil, nil
	}
	return parsed.Result[0], nil
}

func (i *serviceNowInstaller) create(ctx context.Context, table string, fields map[string]any) (string, error) {
	u, err := i.tableURL(table)
	if err != nil {
		return "", err
	}
	b, _ := json.Marshal(fields)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(b))
	if err != nil {
		return "", err
	}
	i.addAuth(req)
	req.Header.Set("Content-Type", "application/json")
	resp, err := i.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("servicenow create %s: %s", table, strings.TrimSpace(string(body)))
	}
	var parsed struct {
		Result map[string]any `json:"result"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", err
	}
	sysID, _ := parsed.Result["sys_id"].(string)
	if strings.TrimSpace(sysID) == "" {
		return "", fmt.Errorf("servicenow create %s: missing sys_id", table)
	}
	return sysID, nil
}

func (i *serviceNowInstaller) updateBySysID(ctx context.Context, table, sysID string, fields map[string]any) error {
	u, err := i.tableURL(table)
	if err != nil {
		return err
	}
	u = strings.TrimRight(u, "/") + "/" + url.PathEscape(sysID)
	b, _ := json.Marshal(fields)
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, u, bytes.NewReader(b))
	if err != nil {
		return err
	}
	i.addAuth(req)
	req.Header.Set("Content-Type", "application/json")
	resp, err := i.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("servicenow update %s: %s", table, strings.TrimSpace(string(body)))
	}
	return nil
}

func (i *serviceNowInstaller) addAuth(req *http.Request) {
	req.SetBasicAuth(i.cfg.AdminUsername, i.cfg.AdminPassword)
	req.Header.Set("Accept", "application/json")
}
