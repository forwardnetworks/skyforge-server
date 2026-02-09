package skyforge

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

var (
	errForwardIntegrationNotConfigured = errors.New("forward servicenow integration not configured")
	errForwardCredsUnavailable         = errors.New("forward credentials unavailable")
)

func resolveForwardCredsForServiceNow(
	ctx context.Context,
	db *sql.DB,
	box *secretBox,
	username string,
	forwardCollectorConfigID string,
	forwardCredentialID string,
	customUsername string,
	customPassword string,
) (string, string, error) {
	username = strings.TrimSpace(username)
	forwardCollectorConfigID = strings.TrimSpace(forwardCollectorConfigID)
	forwardCredentialID = strings.TrimSpace(forwardCredentialID)
	customUsername = strings.TrimSpace(customUsername)
	customPassword = strings.TrimSpace(customPassword)

	if forwardCollectorConfigID == "" {
		if forwardCredentialID != "" {
			if db == nil || box == nil {
				return "", "", errForwardCredsUnavailable
			}
			set, err := getUserForwardCredentialSet(ctx, db, box, username, forwardCredentialID)
			if err != nil || set == nil {
				return "", "", errForwardCredsUnavailable
			}
			u := strings.TrimSpace(set.Username)
			p := strings.TrimSpace(set.Password)
			if u == "" || p == "" {
				return "", "", errForwardCredsUnavailable
			}
			return u, p, nil
		}
		if customUsername == "" || customPassword == "" {
			return "", "", errForwardCredsUnavailable
		}
		return customUsername, customPassword, nil
	}

	if db == nil || box == nil {
		return "", "", errForwardCredsUnavailable
	}

	row := db.QueryRowContext(ctx, `SELECT COALESCE(credential_id,''), forward_username, forward_password
FROM sf_user_forward_collectors
WHERE username=$1 AND id=$2`, username, forwardCollectorConfigID)
	var credID sql.NullString
	var cipherUser, cipherPass sql.NullString
	if err := row.Scan(&credID, &cipherUser, &cipherPass); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", "", fmt.Errorf("%w: selected collector not found", errForwardCredsUnavailable)
		}
		return "", "", fmt.Errorf("%w: failed to load collector creds", errForwardCredsUnavailable)
	}

	if strings.TrimSpace(credID.String) != "" {
		if set, err := getUserForwardCredentialSet(ctx, db, box, username, strings.TrimSpace(credID.String)); err == nil && set != nil {
			plainUser := strings.TrimSpace(set.Username)
			plainPass := strings.TrimSpace(set.Password)
			if plainUser == "" || plainPass == "" {
				return "", "", errForwardCredsUnavailable
			}
			return plainUser, plainPass, nil
		}
		return "", "", errForwardCredsUnavailable
	}

	plainUser, err := box.decrypt(cipherUser.String)
	if err != nil {
		return "", "", fmt.Errorf("%w: failed to decrypt collector username", errForwardCredsUnavailable)
	}
	plainPass, err := box.decrypt(cipherPass.String)
	if err != nil {
		return "", "", fmt.Errorf("%w: failed to decrypt collector password", errForwardCredsUnavailable)
	}
	plainUser = strings.TrimSpace(plainUser)
	plainPass = strings.TrimSpace(plainPass)
	if plainUser == "" || plainPass == "" {
		return "", "", errForwardCredsUnavailable
	}
	return plainUser, plainPass, nil
}

func deleteForwardServiceNowIntegration(ctx context.Context, fwdUsername, fwdPassword string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, defaultServiceNowForwardBaseURL+"/integrations/servicenow", nil)
	if err != nil {
		return err
	}
	req.SetBasicAuth(fwdUsername, fwdPassword)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("forward delete servicenow integration failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return errForwardIntegrationNotConfigured
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		return fmt.Errorf("forward delete servicenow integration: %s", strings.TrimSpace(string(b)))
	}
	return nil
}

func patchForwardServiceNowIntegration(ctx context.Context, fwdUsername, fwdPassword, instanceURL, snUsername, snPassword string) error {
	type payload struct {
		InstanceURL       string `json:"instanceUrl"`
		Username          string `json:"username"`
		Password          string `json:"password"`
		Enabled           bool   `json:"enabled"`
		AutoCreate        bool   `json:"autoCreate"`
		AutoCreateImpact  string `json:"autoCreateImpact"`
		AutoCreateUrgency string `json:"autoCreateUrgency"`
		AutoUpdate        bool   `json:"autoUpdate"`
	}
	body, err := json.Marshal(payload{
		InstanceURL:       instanceURL,
		Username:          snUsername,
		Password:          snPassword,
		Enabled:           true,
		AutoCreate:        true,
		AutoCreateImpact:  "3",
		AutoCreateUrgency: "3",
		AutoUpdate:        true,
	})
	if err != nil {
		return fmt.Errorf("forward patch servicenow integration: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, defaultServiceNowForwardBaseURL+"/integrations/servicenow", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.SetBasicAuth(fwdUsername, fwdPassword)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("forward patch servicenow integration failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		return fmt.Errorf("forward patch servicenow integration: %s", strings.TrimSpace(string(b)))
	}
	return nil
}
