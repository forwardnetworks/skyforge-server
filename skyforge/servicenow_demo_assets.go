package skyforge

import (
	_ "embed"
	"strings"
)

//go:embed servicenow_demo_assets/ForwardClient.js
var servicenowForwardClientJS string

//go:embed servicenow_demo_assets/PathNormalizer.js
var servicenowPathNormalizerJS string

//go:embed servicenow_demo_assets/TicketAnalysis.js
var servicenowTicketAnalysisJS string

//go:embed servicenow_demo_assets/AnalyzeTicket_ScriptAction.js
var servicenowAnalyzeTicketScriptActionJS string

//go:embed servicenow_demo_assets/sp_widget_client.js
var servicenowWidgetClientJS string

//go:embed servicenow_demo_assets/sp_widget_server.js
var servicenowWidgetServerJS string

//go:embed servicenow_demo_assets/sp_widget_template.html
var servicenowWidgetTemplateHTML string

//go:embed servicenow_demo_assets/sp_widget_style.css
var servicenowWidgetStyleCSS string

type servicenowDemoAssets struct {
	ForwardClientJS          string
	PathNormalizerJS         string
	TicketAnalysisJS         string
	AnalyzeTicketScriptJS    string
	WidgetClientJS           string
	WidgetServerJS           string
	WidgetTemplateHTML       string
	WidgetStyleCSS           string
}

func loadServiceNowDemoAssets() servicenowDemoAssets {
	trim := func(s string) string { return strings.TrimSpace(s) + "\n" }
	return servicenowDemoAssets{
		ForwardClientJS:       trim(servicenowForwardClientJS),
		PathNormalizerJS:      trim(servicenowPathNormalizerJS),
		TicketAnalysisJS:      trim(servicenowTicketAnalysisJS),
		AnalyzeTicketScriptJS: trim(servicenowAnalyzeTicketScriptActionJS),
		WidgetClientJS:        trim(servicenowWidgetClientJS),
		WidgetServerJS:        trim(servicenowWidgetServerJS),
		WidgetTemplateHTML:    strings.TrimSpace(servicenowWidgetTemplateHTML) + "\n",
		WidgetStyleCSS:        trim(servicenowWidgetStyleCSS),
	}
}

