package skyforge

import (
	"net/http"
	"strings"
)

func claimsFromAuthUser(user *AuthUser) *SessionClaims {
	if user == nil {
		return nil
	}
	return &SessionClaims{
		Username:      user.Username,
		DisplayName:   user.DisplayName,
		Email:         user.Email,
		Groups:        user.Groups,
		ActorUsername: user.ActorUsername,
	}
}

func claimsFromCookie(sm *SessionManager, cookie string) *SessionClaims {
	if sm == nil || strings.TrimSpace(cookie) == "" {
		return nil
	}
	req := &http.Request{Header: http.Header{"Cookie": []string{cookie}}}
	claims, err := sm.Parse(req)
	if err != nil {
		return nil
	}
	return claims
}
