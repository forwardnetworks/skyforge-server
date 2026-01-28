package skyforge

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"encore.dev"
	"encore.dev/beta/auth"
	"encore.dev/beta/errs"
	"encore.dev/rlog"
)

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type SessionHeaders struct {
	XSkyforgeUsername      string `header:"X-Skyforge-Username" json:"-"`
	XSkyforgeDisplayName   string `header:"X-Skyforge-DisplayName" json:"-"`
	RemoteUser             string `header:"Remote-User" json:"-"`
	XSkyforgeActor         string `header:"X-Skyforge-Actor" json:"-"`
	XSkyforgeImpersonating string `header:"X-Skyforge-Impersonating" json:"-"`
	XSkyforgeEmail         string `header:"X-Skyforge-Email" json:"-"`
	RemoteUserEmail        string `header:"Remote-User-Email" json:"-"`
	XSkyforgeGroups        string `header:"X-Skyforge-Groups" json:"-"`
	XSkyforgeFirstName     string `header:"X-Skyforge-First-Name" json:"-"`
	RemoteUserFirstName    string `header:"Remote-User-First-Name" json:"-"`
	XSkyforgeLastName      string `header:"X-Skyforge-Last-Name" json:"-"`
	RemoteUserLastName     string `header:"Remote-User-Last-Name" json:"-"`
}

func fillSessionHeaders(out *SessionHeaders, claims *SessionClaims) {
	if out == nil || claims == nil {
		return
	}
	out.XSkyforgeUsername = claims.Username
	out.XSkyforgeDisplayName = claims.DisplayName
	out.RemoteUser = claims.Username
	if strings.TrimSpace(claims.ActorUsername) != "" {
		out.XSkyforgeActor = strings.TrimSpace(claims.ActorUsername)
		out.XSkyforgeImpersonating = boolString(isImpersonating(claims))
	}
	if claims.Email != "" {
		out.XSkyforgeEmail = claims.Email
		out.RemoteUserEmail = claims.Email
	}
	if len(claims.Groups) > 0 {
		out.XSkyforgeGroups = strings.Join(claims.Groups, ",")
	}

	firstName := ""
	lastName := ""
	if parts := strings.Fields(strings.TrimSpace(claims.DisplayName)); len(parts) > 0 {
		firstName = parts[0]
		if len(parts) > 1 {
			lastName = strings.Join(parts[1:], " ")
		}
	}
	if firstName != "" {
		out.XSkyforgeFirstName = firstName
		out.RemoteUserFirstName = firstName
	}
	if lastName != "" {
		out.XSkyforgeLastName = lastName
		out.RemoteUserLastName = lastName
	}
}

type LoginResponse struct {
	SetCookie   string      `header:"Set-Cookie" json:"-"`
	UserProfile UserProfile `json:"user"`
}

type LogoutResponse struct {
	SetCookie string `header:"Set-Cookie" json:"-"`
	Status    string `json:"status"`
}

type AuthUserResponse struct {
	UserProfile
}

type SessionResponseEnvelope struct {
	Authenticated bool     `json:"authenticated"`
	Username      string   `json:"username,omitempty"`
	DisplayName   string   `json:"displayName,omitempty"`
	Email         string   `json:"email,omitempty"`
	Groups        []string `json:"groups,omitempty"`
	IsAdmin       bool     `json:"isAdmin,omitempty"`
	ActorUsername string   `json:"actorUsername,omitempty"`
	Impersonating bool     `json:"impersonating,omitempty"`

	XSkyforgeUsername      string `header:"X-Skyforge-Username" json:"-"`
	XSkyforgeDisplayName   string `header:"X-Skyforge-DisplayName" json:"-"`
	RemoteUser             string `header:"Remote-User" json:"-"`
	XSkyforgeActor         string `header:"X-Skyforge-Actor" json:"-"`
	XSkyforgeImpersonating string `header:"X-Skyforge-Impersonating" json:"-"`
	XSkyforgeEmail         string `header:"X-Skyforge-Email" json:"-"`
	RemoteUserEmail        string `header:"Remote-User-Email" json:"-"`
	XSkyforgeGroups        string `header:"X-Skyforge-Groups" json:"-"`
	XSkyforgeFirstName     string `header:"X-Skyforge-First-Name" json:"-"`
	RemoteUserFirstName    string `header:"Remote-User-First-Name" json:"-"`
	XSkyforgeLastName      string `header:"X-Skyforge-Last-Name" json:"-"`
	RemoteUserLastName     string `header:"Remote-User-Last-Name" json:"-"`
}

type SessionHeadResponse struct {
	SessionHeaders
}

type ImpersonateStartRequest struct {
	Username string `json:"username"`
}

type ImpersonateStartResponse struct {
	SetCookie         string `header:"Set-Cookie" json:"-"`
	Status            string `json:"status"`
	EffectiveUsername string `json:"effectiveUsername"`
	ActorUsername     string `json:"actorUsername"`
	Impersonating     bool   `json:"impersonating"`
}

type ImpersonateStopResponse struct {
	SetCookie         string `header:"Set-Cookie" json:"-"`
	Status            string `json:"status"`
	EffectiveUsername string `json:"effectiveUsername"`
	Impersonating     bool   `json:"impersonating"`
}

//encore:api public method=POST path=/api/login
func (s *Service) Login(ctx context.Context, req *LoginRequest) (*LoginResponse, error) {
	loginAttempts.Add(1)
	if req == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid payload").Err()
	}
	if strings.EqualFold(req.Username, "skyforge") && s.cfg.AdminPassword != "" && req.Password == s.cfg.AdminPassword {
		email := "skyforge"
		if domain := strings.TrimSpace(s.cfg.CorpEmailDomain); domain != "" {
			email = "skyforge@" + domain
		}
		profile := &UserProfile{
			Authenticated: true,
			Username:      "skyforge",
			DisplayName:   "Skyforge",
			Email:         email,
			Groups:        nil,
			IsAdmin:       true,
		}
		cookie, err := s.sessionManager.IssueCookieForHeaders(currentHeaders(), profile)
		if err != nil {
			return nil, errs.B().Code(errs.Internal).Msg("failed to create session").Err()
		}
		cacheLDAPPassword(s.db, profile.Username, req.Password, s.cfg.SessionTTL)

		if err := s.userStore.upsert(profile.Username); err != nil {
			rlog.Warn("user store upsert failed", "error", err)
		}
		if s.db != nil {
			writeAuditEvent(ctx, s.db, profile.Username, true, "", "auth.login", "", auditDetailsFromEncore(encore.CurrentRequest()))
		}

		resp := &LoginResponse{UserProfile: *profile}
		resp.SetCookie = cookie.String()
		return resp, nil
	}
	if s.auth == nil {
		loginFailures.Add(1)
		return nil, errs.B().Code(errs.Unauthenticated).Msg("LDAP authentication is disabled").Err()
	}
	profile, err := s.auth.Authenticate(ctx, req.Username, req.Password)
	if err != nil {
		loginFailures.Add(1)
		rlog.Info("login failed", "username", req.Username, "error", err)
		var authErr *AuthFailure
		if errors.As(err, &authErr) {
			return nil, authFailureToError(authErr)
		}
		return nil, errs.B().Code(errs.Unauthenticated).Msg("authentication failed").Err()
	}
	profile.IsAdmin = isAdminUser(s.cfg, profile.Username)

	cookie, err := s.sessionManager.IssueCookieForHeaders(currentHeaders(), profile)
	if err != nil {
		return nil, errs.B().Code(errs.Internal).Msg("failed to create session").Err()
	}
	cacheLDAPPassword(s.db, profile.Username, req.Password, s.cfg.SessionTTL)

	if err := s.userStore.upsert(profile.Username); err != nil {
		rlog.Warn("user store upsert failed", "error", err)
	}
	if s.db != nil {
		writeAuditEvent(ctx, s.db, profile.Username, isAdminUser(s.cfg, profile.Username), "", "auth.login", "", auditDetailsFromEncore(encore.CurrentRequest()))
	}

	resp := &LoginResponse{UserProfile: *profile}
	resp.SetCookie = cookie.String()
	return resp, nil
}

//encore:api public method=POST path=/auth/login
func (s *Service) AuthLogin(ctx context.Context, req *LoginRequest) (*LoginResponse, error) {
	return s.Login(ctx, req)
}

//encore:api public method=POST path=/api/logout
func (s *Service) Logout(ctx context.Context) (*LogoutResponse, error) {
	if s.db != nil {
		if claims := claimsFromCookie(s.sessionManager, currentHeaders().Get("Cookie")); claims != nil {
			writeAuditEvent(ctx, s.db, claims.Username, isAdminUser(s.cfg, claims.Username), "", "auth.logout", "", auditDetailsFromEncore(encore.CurrentRequest()))
			clearCachedLDAPPassword(s.db, claims.Username)
		}
	}
	resp := &LogoutResponse{Status: "logged out"}
	resp.SetCookie = s.sessionManager.ClearCookie().String()
	return resp, nil
}

// Reauth clears the current session cookie (and any cached LDAP password) and redirects
// back to the Skyforge login page, preserving the requested next hop.
//
//encore:api public raw method=GET path=/api/reauth
func (s *Service) Reauth(w http.ResponseWriter, r *http.Request) {
	next := strings.TrimSpace(r.URL.Query().Get("next"))
	if next == "" {
		next = "/"
	}
	if !strings.HasPrefix(next, "/") {
		next = "/"
	}

	if claims := claimsFromCookie(s.sessionManager, r.Header.Get("Cookie")); claims != nil {
		clearCachedLDAPPassword(s.db, claims.Username)
	}
	http.SetCookie(w, s.sessionManager.ClearCookie())
	if s.oidc != nil {
		http.Redirect(w, r, "/api/oidc/login?next="+url.QueryEscape(next), http.StatusFound)
		return
	}
	http.Redirect(w, r, "/status?signin=1&next="+url.QueryEscape(next), http.StatusFound)
}

//encore:api public method=POST path=/auth/logout
func (s *Service) AuthLogout(ctx context.Context) (*LogoutResponse, error) {
	return s.Logout(ctx)
}

//encore:api auth method=POST path=/auth/logout-all
func (s *Service) AuthLogoutAll(ctx context.Context) (*LogoutResponse, error) {
	return s.Logout(ctx)
}

//encore:api public method=GET path=/api/session
func (s *Service) Session(ctx context.Context) (*SessionResponseEnvelope, error) {
	claims := claimsFromCookie(s.sessionManager, currentHeaders().Get("Cookie"))
	if claims == nil {
		return &SessionResponseEnvelope{Authenticated: false}, nil
	}
	resp := &SessionResponseEnvelope{
		Authenticated: true,
		Username:      claims.Username,
		DisplayName:   claims.DisplayName,
		Email:         claims.Email,
		Groups:        claims.Groups,
		IsAdmin:       isAdminForClaims(s.cfg, claims),
		ActorUsername: claims.ActorUsername,
		Impersonating: isImpersonating(claims),
	}
	fillSessionHeadersEnvelope(resp, claims)
	return resp, nil
}

//encore:api auth method=POST path=/auth/refresh
func (s *Service) AuthRefresh(ctx context.Context) (*SessionResponseEnvelope, error) {
	return s.Session(ctx)
}

//encore:api auth method=POST path=/auth/validate-token
func (s *Service) AuthValidateToken(ctx context.Context) (*AuthUserResponse, error) {
	user, ok := auth.Data().(*AuthUser)
	if !ok || user == nil {
		return nil, errs.B().Code(errs.Unauthenticated).Msg("authentication required").Err()
	}
	resp := &AuthUserResponse{UserProfile: *authUserToProfile(user)}
	return resp, nil
}

//encore:api public method=HEAD path=/api/session
func (s *Service) SessionHead(ctx context.Context) (*SessionHeadResponse, error) {
	resp := &SessionHeadResponse{}
	if claims := claimsFromCookie(s.sessionManager, currentHeaders().Get("Cookie")); claims != nil {
		fillSessionHeaders(&resp.SessionHeaders, claims)
	}
	return resp, nil
}

func fillSessionHeadersEnvelope(out *SessionResponseEnvelope, claims *SessionClaims) {
	if out == nil || claims == nil {
		return
	}
	out.XSkyforgeUsername = claims.Username
	out.XSkyforgeDisplayName = claims.DisplayName
	out.RemoteUser = claims.Username
	if strings.TrimSpace(claims.ActorUsername) != "" {
		out.XSkyforgeActor = strings.TrimSpace(claims.ActorUsername)
		out.XSkyforgeImpersonating = boolString(isImpersonating(claims))
	}
	if claims.Email != "" {
		out.XSkyforgeEmail = claims.Email
		out.RemoteUserEmail = claims.Email
	}
	if len(claims.Groups) > 0 {
		out.XSkyforgeGroups = strings.Join(claims.Groups, ",")
	}

	firstName := ""
	lastName := ""
	if parts := strings.Fields(strings.TrimSpace(claims.DisplayName)); len(parts) > 0 {
		firstName = parts[0]
		if len(parts) > 1 {
			lastName = strings.Join(parts[1:], " ")
		}
	}
	if firstName != "" {
		out.XSkyforgeFirstName = firstName
		out.RemoteUserFirstName = firstName
	}
	if lastName != "" {
		out.XSkyforgeLastName = lastName
		out.RemoteUserLastName = lastName
	}
}

func authUserToProfile(user *AuthUser) *UserProfile {
	if user == nil {
		return &UserProfile{Authenticated: false}
	}
	displayName := user.DisplayName
	if strings.TrimSpace(displayName) == "" {
		displayName = user.Username
	}
	return &UserProfile{
		Authenticated: true,
		Username:      user.Username,
		DisplayName:   displayName,
		Email:         user.Email,
		Groups:        user.Groups,
		IsAdmin:       user.IsAdmin,
		ActorUsername: user.ActorUsername,
		Impersonating: user.Impersonating,
	}
}

type nginxSessionPayload struct {
	Status string `json:"status,omitempty"`
}

type forwardAuthSessionPayload struct {
	Status string `json:"status,omitempty"`
}

// SessionForwardAuth is a Skyforge SSO gate compatible endpoint used by Traefik forwardAuth.
//
//encore:api public raw method=GET path=/api/session/forwardauth
func (s *Service) SessionForwardAuth(w http.ResponseWriter, req *http.Request) {
	claims := claimsFromCookie(s.sessionManager, req.Header.Get("Cookie"))
	if claims == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(&forwardAuthSessionPayload{Status: "unauthenticated"})
		return
	}
	addSessionHeaders(w.Header(), claims)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(&forwardAuthSessionPayload{Status: "ok"})
}

// SessionForwardAuthHead is a Skyforge SSO gate compatible endpoint used by Traefik forwardAuth (HEAD).
//
//encore:api public raw method=HEAD path=/api/session/forwardauth
func (s *Service) SessionForwardAuthHead(w http.ResponseWriter, req *http.Request) {
	claims := claimsFromCookie(s.sessionManager, req.Header.Get("Cookie"))
	if claims == nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	addSessionHeaders(w.Header(), claims)
	w.WriteHeader(http.StatusOK)
}

//encore:api auth method=POST path=/api/admin/impersonate/start tag:admin
func (s *Service) AdminImpersonateStart(ctx context.Context, req *ImpersonateStartRequest) (*ImpersonateStartResponse, error) {
	if req == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid payload").Err()
	}
	actor := auth.Data()
	authUser, ok := actor.(*AuthUser)
	if !ok || authUser == nil {
		return nil, errs.B().Code(errs.Unauthenticated).Msg("authentication required").Err()
	}
	claims := claimsFromCookie(s.sessionManager, currentHeaders().Get("Cookie"))
	if claims == nil {
		return nil, errs.B().Code(errs.Unauthenticated).Msg("authentication required").Err()
	}
	if strings.TrimSpace(claims.ActorUsername) != "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("already impersonating").Err()
	}

	target := strings.TrimSpace(req.Username)
	if !isValidUsername(target) {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid username").Err()
	}
	if strings.EqualFold(target, claims.Username) {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("cannot impersonate yourself").Err()
	}

	targetProfile := &UserProfile{
		Authenticated: true,
		Username:      target,
		DisplayName:   target,
		Groups:        []string{},
	}
	ctxLookup, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if lookedUp, err := lookupLDAPUserProfile(ctxLookup, s.cfg.LDAP, target, s.cfg.MaxGroups, s.cfg.LDAPLookupBindDN, s.cfg.LDAPLookupBindPassword); err == nil && lookedUp != nil {
		targetProfile = lookedUp
	}
	targetProfile.IsAdmin = isAdminUser(s.cfg, targetProfile.Username)

	cookie, err := s.sessionManager.IssueImpersonatedCookieForHeaders(currentHeaders(), claims, targetProfile)
	if err != nil {
		return nil, errs.B().Code(errs.Internal).Msg("failed to create impersonated session").Err()
	}
	if err := s.userStore.upsert(targetProfile.Username); err != nil {
		rlog.Warn("user store upsert failed", "error", err)
	}
	if s.db != nil {
		writeAuditEvent(ctx, s.db, authUser.Username, true, targetProfile.Username, "admin.impersonate.start", "", "")
	}

	resp := &ImpersonateStartResponse{
		Status:            "ok",
		EffectiveUsername: targetProfile.Username,
		ActorUsername:     authUser.Username,
		Impersonating:     true,
	}
	resp.SetCookie = cookie.String()
	return resp, nil
}

//encore:api auth method=POST path=/api/admin/impersonate/stop tag:admin
func (s *Service) AdminImpersonateStop(ctx context.Context) (*ImpersonateStopResponse, error) {
	claims := claimsFromCookie(s.sessionManager, currentHeaders().Get("Cookie"))
	if claims == nil {
		return nil, errs.B().Code(errs.Unauthenticated).Msg("authentication required").Err()
	}
	if strings.TrimSpace(claims.ActorUsername) == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("not impersonating").Err()
	}
	if !isAdminUser(s.cfg, claims.ActorUsername) {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}

	adminProfile := &UserProfile{
		Authenticated: true,
		Username:      claims.ActorUsername,
		DisplayName:   claims.ActorDisplayName,
		Email:         claims.ActorEmail,
		Groups:        claims.ActorGroups,
		IsAdmin:       true,
	}
	if strings.TrimSpace(adminProfile.DisplayName) == "" {
		adminProfile.DisplayName = adminProfile.Username
	}

	cookie, err := s.sessionManager.IssueCookieForHeaders(currentHeaders(), adminProfile)
	if err != nil {
		return nil, errs.B().Code(errs.Internal).Msg("failed to restore session").Err()
	}
	if s.db != nil {
		writeAuditEvent(ctx, s.db, adminProfile.Username, true, claims.Username, "admin.impersonate.stop", "", "")
	}

	resp := &ImpersonateStopResponse{
		Status:            "ok",
		EffectiveUsername: adminProfile.Username,
		Impersonating:     false,
	}
	resp.SetCookie = cookie.String()
	return resp, nil
}

func authFailureToError(authErr *AuthFailure) error {
	if authErr == nil {
		return errs.B().Code(errs.Unauthenticated).Msg("authentication failed").Err()
	}
	switch authErr.Status {
	case http.StatusUnauthorized:
		return errs.B().Code(errs.Unauthenticated).Msg(authErr.PublicMessage).Err()
	case http.StatusBadRequest:
		return errs.B().Code(errs.InvalidArgument).Msg(authErr.PublicMessage).Err()
	default:
		return errs.B().Code(errs.Unavailable).Msg(authErr.PublicMessage).Err()
	}
}

func currentHeaders() http.Header {
	return encore.CurrentRequest().Headers
}

func auditDetailsFromEncore(req *encore.Request) string {
	if req == nil {
		return ""
	}
	host := strings.TrimSpace(req.Headers.Get("Host"))
	if host == "" {
		host = strings.TrimSpace(req.Headers.Get("X-Forwarded-Host"))
	}
	httpReq := &http.Request{
		Method: "",
		Header: req.Headers,
		URL:    &url.URL{Path: req.Path},
		Host:   host,
		Proto:  req.Headers.Get("X-Forwarded-Proto"),
	}
	return auditRequestDetails(httpReq)
}
