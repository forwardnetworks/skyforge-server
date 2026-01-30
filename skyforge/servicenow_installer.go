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

func newServiceNowInstaller(cfg serviceNowInstallerConfig) *serviceNowInstaller {
	return &serviceNowInstaller{
		cfg: cfg,
		client: &http.Client{
			Timeout: 20 * time.Second,
		},
	}
}

type serviceNowDemoTableNames struct {
	Ticket string
	Hop    string
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
	// The schema (tables/fields) is a manual step due to ServiceNow platform complexity and Table API restrictions.
	names, err := i.resolveDemoTableNames(ctx)
	if err != nil {
		return err
	}
	if err := i.ensureProperties(ctx, names); err != nil {
		return err
	}
	if missing, err := i.checkSchema(ctx); err != nil {
		return err
	} else if len(missing) > 0 {
		return fmt.Errorf("servicenow schema not installed; create required tables/fields in ServiceNow and retry (missing: %s)", strings.Join(missing, ", "))
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

func (i *serviceNowInstaller) resolveDemoTableNames(ctx context.Context) (serviceNowDemoTableNames, error) {
	// Prefer "u_*" names (Global scope default) to keep manual setup dead simple; fall back to the older "x_*" names.
	candidates := []serviceNowDemoTableNames{
		{Ticket: "u_forward_connectivity_ticket", Hop: "u_forward_connectivity_hop"},
		{Ticket: "x_fwd_demo_connectivity_ticket", Hop: "x_fwd_demo_connectivity_hop"},
	}

	for _, c := range candidates {
		t, err := i.findByField(ctx, "sys_db_object", "name", c.Ticket)
		if err != nil {
			return serviceNowDemoTableNames{}, fmt.Errorf("schema lookup %s: %w", c.Ticket, err)
		}
		h, err := i.findByField(ctx, "sys_db_object", "name", c.Hop)
		if err != nil {
			return serviceNowDemoTableNames{}, fmt.Errorf("schema lookup %s: %w", c.Hop, err)
		}
		if t != nil && h != nil {
			return c, nil
		}
	}

	// No schema detected yet; return the preferred names so Skyforge can guide users toward the simplest setup.
	return candidates[0], nil
}

func (i *serviceNowInstaller) checkSchema(ctx context.Context) ([]string, error) {
	names, err := i.resolveDemoTableNames(ctx)
	if err != nil {
		return nil, err
	}

	// Required tables.
	requiredTables := []string{
		names.Ticket,
		names.Hop,
	}
	var missing []string
	for _, t := range requiredTables {
		obj, err := i.findByField(ctx, "sys_db_object", "name", t)
		if err != nil {
			return nil, fmt.Errorf("schema lookup %s: %w", t, err)
		}
		if obj == nil {
			missing = append(missing, "table:"+t)
		}
	}

	// Required fields.
	requiredFields := []struct {
		Table   string
		Element string
	}{
		// Ticket flow input
		{Table: names.Ticket, Element: "u_src_ip"},
		{Table: names.Ticket, Element: "u_dst_ip"},
		{Table: names.Ticket, Element: "u_protocol"},
		{Table: names.Ticket, Element: "u_dst_port"},

		// Forward selection
		{Table: names.Ticket, Element: "u_forward_network_id"},
		{Table: names.Ticket, Element: "u_forward_snapshot_id"},

		// Analysis results
		{Table: names.Ticket, Element: "u_allowed"},
		{Table: names.Ticket, Element: "u_block_category"},
		{Table: names.Ticket, Element: "u_block_device"},
		{Table: names.Ticket, Element: "u_block_interface"},
		{Table: names.Ticket, Element: "u_block_rule"},
		{Table: names.Ticket, Element: "u_block_reason"},
		{Table: names.Ticket, Element: "u_forward_query_url"},
		{Table: names.Ticket, Element: "u_raw_excerpt"},

		// Analysis state
		{Table: names.Ticket, Element: "u_analysis_status"},
		{Table: names.Ticket, Element: "u_analysis_error"},

		// Hop table
		{Table: names.Hop, Element: "u_ticket"},
		{Table: names.Hop, Element: "u_hop_index"},
		{Table: names.Hop, Element: "u_device"},
		{Table: names.Hop, Element: "u_ingress"},
		{Table: names.Hop, Element: "u_egress"},
		{Table: names.Hop, Element: "u_note"},
	}
	for _, f := range requiredFields {
		query := fmt.Sprintf("name=%s^element=%s", f.Table, f.Element)
		existing, err := i.findByQuery(ctx, "sys_dictionary", query)
		if err != nil {
			return nil, fmt.Errorf("schema lookup %s.%s: %w", f.Table, f.Element, err)
		}
		if existing == nil {
			missing = append(missing, "field:"+f.Table+"."+f.Element)
		}
	}

	return missing, nil
}

func (i *serviceNowInstaller) ensureProperties(ctx context.Context, names serviceNowDemoTableNames) error {
	props := map[string]string{
		"x_fwd_demo.forward.base_url":    strings.TrimRight(i.cfg.ForwardBaseURL, "/"),
		"x_fwd_demo.forward.max_results": "1",
		"x_fwd_demo.forward.username":    strings.TrimSpace(i.cfg.ForwardUsername),
		"x_fwd_demo.forward.password":    strings.TrimSpace(i.cfg.ForwardPassword),
		"x_fwd_demo.tables.ticket":       strings.TrimSpace(names.Ticket),
		"x_fwd_demo.tables.hop":          strings.TrimSpace(names.Hop),
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
				"name":            k,
				"value":           v,
				"rest_message_fn": sysID,
				"parameter_type":  "query",
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
			"name":   inc.Name,
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
		"name":       actionName,
		"active":     true,
		"event_name": eventName,
		"script":     i.cfg.Assets.AnalyzeTicketScriptJS,
	}); err != nil {
		// Some PDIs (or Table API restrictions) report "Invalid table sys_script_action".
		// The demo can run without this record because the Service Portal widget uses
		// a synchronous analysis path.
		if strings.Contains(err.Error(), "Invalid table sys_script_action") {
			return nil
		}
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
