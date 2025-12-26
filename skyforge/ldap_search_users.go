package skyforge

import (
	"context"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

func ldapUsernameAttrFromTemplate(bindTemplate string) string {
	bindTemplate = strings.TrimSpace(bindTemplate)
	if bindTemplate == "" {
		return "uid"
	}
	// Try to parse "attr=%s,..." from the bind template.
	if strings.Contains(bindTemplate, "=") {
		parts := strings.SplitN(bindTemplate, "=", 2)
		attr := strings.TrimSpace(parts[0])
		if attr != "" && !strings.ContainsAny(attr, " ,") {
			return attr
		}
	}
	return "uid"
}

func ldapBaseDNFromTemplateOrConfig(cfg LDAPConfig) string {
	if strings.TrimSpace(cfg.BaseDN) != "" {
		return strings.TrimSpace(cfg.BaseDN)
	}
	template := strings.TrimSpace(cfg.BindTemplate)
	if template == "" {
		return ""
	}
	if idx := strings.Index(template, ","); idx >= 0 && idx+1 < len(template) {
		return strings.TrimSpace(template[idx+1:])
	}
	return ""
}

func searchLDAPUsers(ctx context.Context, cfg LDAPConfig, query string, bindDN string, bindPassword string, limit int) ([]AssignableUser, error) {
	query = strings.ToLower(strings.TrimSpace(query))
	if query == "" {
		return []AssignableUser{}, nil
	}
	baseDN := ldapBaseDNFromTemplateOrConfig(cfg)
	if baseDN == "" {
		return []AssignableUser{}, nil
	}

	usernameAttr := ldapUsernameAttrFromTemplate(cfg.BindTemplate)
	displayAttr := strings.TrimSpace(cfg.DisplayNameAttr)
	if displayAttr == "" {
		displayAttr = "cn"
	}
	mailAttr := strings.TrimSpace(cfg.MailAttr)
	if mailAttr == "" {
		mailAttr = "mail"
	}

	conn, err := dialLDAP(cfg)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if err := startTLSSafely(conn, cfg); err != nil {
		return nil, err
	}
	if strings.TrimSpace(bindDN) != "" {
		if err := conn.Bind(strings.TrimSpace(bindDN), bindPassword); err != nil {
			return nil, err
		}
	}

	escaped := ldap.EscapeFilter(query)
	filter := "(|(objectClass=person)(" + usernameAttr + "=*" + escaped + "*)(" + displayAttr + "=*" + escaped + "*)(" + mailAttr + "=*" + escaped + "*))"
	attrs := []string{usernameAttr, displayAttr, mailAttr}
	sizeLimit := limit
	if sizeLimit <= 0 {
		sizeLimit = 30
	}

	req := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		sizeLimit,
		0,
		false,
		filter,
		attrs,
		nil,
	)
	_ = ctx
	res, err := conn.Search(req)
	if err != nil {
		return nil, err
	}

	seen := map[string]struct{}{}
	out := make([]AssignableUser, 0, len(res.Entries))
	for _, entry := range res.Entries {
		if entry == nil {
			continue
		}
		u := strings.ToLower(strings.TrimSpace(entry.GetAttributeValue(usernameAttr)))
		if u == "" {
			continue
		}
		if strings.EqualFold(u, "skyforge") || strings.EqualFold(u, "admin") || strings.EqualFold(u, "system") {
			continue
		}
		if _, ok := seen[u]; ok {
			continue
		}
		seen[u] = struct{}{}
		display := strings.TrimSpace(entry.GetAttributeValue(displayAttr))
		if display == "" {
			display = u
		}
		email := strings.TrimSpace(entry.GetAttributeValue(mailAttr))
		out = append(out, AssignableUser{
			ID:       u,
			Username: u,
			Display:  display,
			Email:    email,
		})
	}

	return out, nil
}
