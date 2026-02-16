package skyforge

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

const scopeServerRefPrefix = "ws:"

type scopeNetlabServer struct {
	ID            string
	OwnerUsername string
	Name          string
	APIURL        string
	APIInsecure   bool
	APIUser       string
	APIPassword   string
	APIToken      string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

type scopeEveServer struct {
	ID            string
	OwnerUsername string
	Name          string
	APIURL        string
	WebURL        string
	SkipTLSVerify bool
	APIUser       string
	APIPassword   string
	SSHHost       string
	SSHUser       string
	SSHKey        string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

func scopeServerRef(id string) string {
	id = strings.TrimSpace(id)
	if id == "" {
		return ""
	}
	return scopeServerRefPrefix + id
}

func parseOwnerServerRef(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", false
	}
	if after, ok := strings.CutPrefix(value, scopeServerRefPrefix); ok {
		id := after
		id = strings.TrimSpace(id)
		if id == "" {
			return "", false
		}
		return id, true
	}
	return "", false
}

func listOwnerNetlabServers(ctx context.Context, db *sql.DB, box *secretBox, ownerID string) ([]scopeNetlabServer, error) {
	if db == nil {
		return nil, fmt.Errorf("db is not configured")
	}
	ownerID = strings.TrimSpace(ownerID)
	if ownerID == "" {
		return nil, fmt.Errorf("owner username is required")
	}
	rows, err := db.QueryContext(ctx, `SELECT id, project_id, name, api_url, api_insecure, COALESCE(api_user,''), COALESCE(api_password,''), COALESCE(api_token,''), created_at, updated_at
FROM sf_project_netlab_servers WHERE project_id=$1 ORDER BY name ASC`, ownerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []scopeNetlabServer{}
	for rows.Next() {
		var id, projectID, name, apiURL string
		var insecure bool
		var apiUser, apiPasswordEnc string
		var tokenEnc string
		var createdAt, updatedAt time.Time
		if err := rows.Scan(&id, &projectID, &name, &apiURL, &insecure, &apiUser, &apiPasswordEnc, &tokenEnc, &createdAt, &updatedAt); err != nil {
			return nil, err
		}
		apiPassword := strings.TrimSpace(apiPasswordEnc)
		if apiPassword != "" && box != nil {
			if decrypted, err := box.decrypt(apiPassword); err == nil {
				apiPassword = strings.TrimSpace(decrypted)
			}
		}
		token := strings.TrimSpace(tokenEnc)
		if token != "" && box != nil {
			if decrypted, err := box.decrypt(token); err == nil {
				token = strings.TrimSpace(decrypted)
			}
		}
		out = append(out, scopeNetlabServer{
			ID:            id,
			OwnerUsername: projectID,
			Name:          strings.TrimSpace(name),
			APIURL:        strings.TrimSpace(apiURL),
			APIInsecure:   insecure,
			APIUser:       strings.TrimSpace(apiUser),
			APIPassword:   apiPassword,
			APIToken:      token,
			CreatedAt:     createdAt,
			UpdatedAt:     updatedAt,
		})
	}
	return out, nil
}

func getOwnerNetlabServerByID(ctx context.Context, db *sql.DB, box *secretBox, ownerID, id string) (*scopeNetlabServer, error) {
	if db == nil {
		return nil, fmt.Errorf("db is not configured")
	}
	ownerID = strings.TrimSpace(ownerID)
	id = strings.TrimSpace(id)
	if ownerID == "" || id == "" {
		return nil, nil
	}
	var rec scopeNetlabServer
	var apiUser, apiPasswordEnc string
	var tokenEnc string
	err := db.QueryRowContext(ctx, `SELECT id, project_id, name, api_url, api_insecure, COALESCE(api_user,''), COALESCE(api_password,''), COALESCE(api_token,''), created_at, updated_at
FROM sf_project_netlab_servers WHERE project_id=$1 AND id=$2`, ownerID, id).Scan(
		&rec.ID, &rec.OwnerUsername, &rec.Name, &rec.APIURL, &rec.APIInsecure, &apiUser, &apiPasswordEnc, &tokenEnc, &rec.CreatedAt, &rec.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	rec.Name = strings.TrimSpace(rec.Name)
	rec.APIURL = strings.TrimSpace(rec.APIURL)
	rec.APIUser = strings.TrimSpace(apiUser)
	apiPassword := strings.TrimSpace(apiPasswordEnc)
	if apiPassword != "" && box != nil {
		if decrypted, err := box.decrypt(apiPassword); err == nil {
			apiPassword = strings.TrimSpace(decrypted)
		}
	}
	rec.APIPassword = apiPassword
	token := strings.TrimSpace(tokenEnc)
	if token != "" && box != nil {
		if decrypted, err := box.decrypt(token); err == nil {
			token = strings.TrimSpace(decrypted)
		}
	}
	rec.APIToken = token
	return &rec, nil
}

func upsertOwnerNetlabServer(ctx context.Context, db *sql.DB, box *secretBox, rec scopeNetlabServer) (*scopeNetlabServer, error) {
	if db == nil {
		return nil, fmt.Errorf("db is not configured")
	}
	rec.OwnerUsername = strings.TrimSpace(rec.OwnerUsername)
	rec.Name = strings.TrimSpace(rec.Name)
	rec.APIURL = strings.TrimSpace(rec.APIURL)
	rec.APIUser = strings.TrimSpace(rec.APIUser)
	rec.APIPassword = strings.TrimSpace(rec.APIPassword)
	rec.APIToken = strings.TrimSpace(rec.APIToken)
	if rec.OwnerUsername == "" {
		return nil, fmt.Errorf("owner username is required")
	}
	if rec.Name == "" || rec.APIURL == "" {
		return nil, fmt.Errorf("name and apiUrl are required")
	}
	id := strings.TrimSpace(rec.ID)
	if id == "" {
		id = uuid.NewString()
	}
	if rec.APIPassword == "" && strings.TrimSpace(rec.ID) != "" {
		if existing, err := getOwnerNetlabServerByID(ctx, db, box, rec.OwnerUsername, rec.ID); err == nil && existing != nil {
			rec.APIUser = strings.TrimSpace(existing.APIUser)
			rec.APIPassword = strings.TrimSpace(existing.APIPassword)
			rec.APIToken = strings.TrimSpace(existing.APIToken)
		}
	}
	passwordEnc := strings.TrimSpace(rec.APIPassword)
	if passwordEnc != "" && box != nil {
		enc, err := encryptIfPlain(box, passwordEnc)
		if err != nil {
			return nil, err
		}
		passwordEnc = enc
	}
	tokenEnc := strings.TrimSpace(rec.APIToken)
	if tokenEnc != "" && box != nil {
		enc, err := encryptIfPlain(box, tokenEnc)
		if err != nil {
			return nil, err
		}
		tokenEnc = enc
	}
	_, err := db.ExecContext(ctx, `INSERT INTO sf_project_netlab_servers (
  id, project_id, name, api_url, api_insecure, api_user, api_password, api_token, created_at, updated_at
) VALUES ($1,$2,$3,$4,$5,NULLIF($6,''),NULLIF($7,''),NULLIF($8,''),now(),now())
ON CONFLICT (id) DO UPDATE SET
  name=excluded.name,
  api_url=excluded.api_url,
  api_insecure=excluded.api_insecure,
  api_user=excluded.api_user,
  api_password=excluded.api_password,
  api_token=excluded.api_token,
  updated_at=now()`,
		id, rec.OwnerUsername, rec.Name, rec.APIURL, rec.APIInsecure, rec.APIUser, passwordEnc, tokenEnc,
	)
	if err != nil {
		return nil, err
	}
	out := rec
	out.ID = id
	out.APIToken = strings.TrimSpace(rec.APIToken)
	out.APIPassword = strings.TrimSpace(rec.APIPassword)
	return &out, nil
}

func deleteOwnerNetlabServer(ctx context.Context, db *sql.DB, ownerID, id string) error {
	if db == nil {
		return fmt.Errorf("db is not configured")
	}
	ownerID = strings.TrimSpace(ownerID)
	id = strings.TrimSpace(id)
	if ownerID == "" || id == "" {
		return nil
	}
	_, err := db.ExecContext(ctx, `DELETE FROM sf_project_netlab_servers WHERE project_id=$1 AND id=$2`, ownerID, id)
	return err
}

func listOwnerEveServers(ctx context.Context, db *sql.DB, box *secretBox, ownerID string) ([]scopeEveServer, error) {
	if db == nil {
		return nil, fmt.Errorf("db is not configured")
	}
	ownerID = strings.TrimSpace(ownerID)
	if ownerID == "" {
		return nil, fmt.Errorf("owner username is required")
	}
	rows, err := db.QueryContext(ctx, `SELECT id, project_id, name, api_url, COALESCE(web_url,''), skip_tls_verify,
  COALESCE(api_user,''), COALESCE(api_password,''), COALESCE(ssh_host,''), COALESCE(ssh_user,''), COALESCE(ssh_key,''), created_at, updated_at
FROM sf_project_eve_servers WHERE project_id=$1 ORDER BY name ASC`, ownerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []scopeEveServer{}
	for rows.Next() {
		var rec scopeEveServer
		var webURL string
		var apiUser, apiPasswordEnc, sshHost, sshUser, sshKeyEnc string
		if err := rows.Scan(
			&rec.ID,
			&rec.OwnerUsername,
			&rec.Name,
			&rec.APIURL,
			&webURL,
			&rec.SkipTLSVerify,
			&apiUser,
			&apiPasswordEnc,
			&sshHost,
			&sshUser,
			&sshKeyEnc,
			&rec.CreatedAt,
			&rec.UpdatedAt,
		); err != nil {
			return nil, err
		}
		rec.Name = strings.TrimSpace(rec.Name)
		rec.APIURL = strings.TrimSpace(rec.APIURL)
		rec.WebURL = strings.TrimSpace(webURL)
		rec.APIUser = strings.TrimSpace(apiUser)
		apiPassword := strings.TrimSpace(apiPasswordEnc)
		if apiPassword != "" && box != nil {
			if decrypted, err := box.decrypt(apiPassword); err == nil {
				apiPassword = strings.TrimSpace(decrypted)
			}
		}
		rec.APIPassword = apiPassword
		rec.SSHHost = strings.TrimSpace(sshHost)
		rec.SSHUser = strings.TrimSpace(sshUser)
		sshKey := strings.TrimSpace(sshKeyEnc)
		if sshKey != "" && box != nil {
			if decrypted, err := box.decrypt(sshKey); err == nil {
				sshKey = strings.TrimSpace(decrypted)
			}
		}
		rec.SSHKey = sshKey
		out = append(out, rec)
	}
	return out, nil
}

func getOwnerEveServerByID(ctx context.Context, db *sql.DB, box *secretBox, ownerID, id string) (*scopeEveServer, error) {
	if db == nil {
		return nil, fmt.Errorf("db is not configured")
	}
	ownerID = strings.TrimSpace(ownerID)
	id = strings.TrimSpace(id)
	if ownerID == "" || id == "" {
		return nil, nil
	}
	var rec scopeEveServer
	var webURL, apiUser, apiPasswordEnc, sshHost, sshUser, sshKeyEnc string
	err := db.QueryRowContext(ctx, `SELECT id, project_id, name, api_url, COALESCE(web_url,''), skip_tls_verify,
  COALESCE(api_user,''), COALESCE(api_password,''), COALESCE(ssh_host,''), COALESCE(ssh_user,''), COALESCE(ssh_key,''), created_at, updated_at
FROM sf_project_eve_servers WHERE project_id=$1 AND id=$2`, ownerID, id).Scan(
		&rec.ID, &rec.OwnerUsername, &rec.Name, &rec.APIURL, &webURL, &rec.SkipTLSVerify,
		&apiUser, &apiPasswordEnc, &sshHost, &sshUser, &sshKeyEnc, &rec.CreatedAt, &rec.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	rec.Name = strings.TrimSpace(rec.Name)
	rec.APIURL = strings.TrimSpace(rec.APIURL)
	rec.WebURL = strings.TrimSpace(webURL)
	rec.APIUser = strings.TrimSpace(apiUser)
	apiPassword := strings.TrimSpace(apiPasswordEnc)
	if apiPassword != "" && box != nil {
		if decrypted, err := box.decrypt(apiPassword); err == nil {
			apiPassword = strings.TrimSpace(decrypted)
		}
	}
	rec.APIPassword = apiPassword
	rec.SSHHost = strings.TrimSpace(sshHost)
	rec.SSHUser = strings.TrimSpace(sshUser)
	sshKey := strings.TrimSpace(sshKeyEnc)
	if sshKey != "" && box != nil {
		if decrypted, err := box.decrypt(sshKey); err == nil {
			sshKey = strings.TrimSpace(decrypted)
		}
	}
	rec.SSHKey = sshKey
	return &rec, nil
}

func upsertOwnerEveServer(ctx context.Context, db *sql.DB, box *secretBox, rec scopeEveServer) (*scopeEveServer, error) {
	if db == nil {
		return nil, fmt.Errorf("db is not configured")
	}
	rec.OwnerUsername = strings.TrimSpace(rec.OwnerUsername)
	rec.Name = strings.TrimSpace(rec.Name)
	rec.APIURL = strings.TrimSpace(rec.APIURL)
	rec.WebURL = strings.TrimSpace(rec.WebURL)
	rec.APIUser = strings.TrimSpace(rec.APIUser)
	rec.APIPassword = strings.TrimSpace(rec.APIPassword)
	rec.SSHHost = strings.TrimSpace(rec.SSHHost)
	rec.SSHUser = strings.TrimSpace(rec.SSHUser)
	rec.SSHKey = strings.TrimSpace(rec.SSHKey)
	if rec.OwnerUsername == "" {
		return nil, fmt.Errorf("owner username is required")
	}
	if rec.Name == "" || rec.APIURL == "" {
		return nil, fmt.Errorf("name and apiUrl are required")
	}
	id := strings.TrimSpace(rec.ID)
	if id == "" {
		id = uuid.NewString()
	}
	if rec.APIPassword == "" && strings.TrimSpace(rec.ID) != "" {
		if existing, err := getOwnerEveServerByID(ctx, db, box, rec.OwnerUsername, rec.ID); err == nil && existing != nil {
			rec.APIUser = strings.TrimSpace(existing.APIUser)
			rec.APIPassword = strings.TrimSpace(existing.APIPassword)
		}
	}
	passwordEnc := strings.TrimSpace(rec.APIPassword)
	if passwordEnc != "" && box != nil {
		enc, err := encryptIfPlain(box, passwordEnc)
		if err != nil {
			return nil, err
		}
		passwordEnc = enc
	}
	sshKeyEnc := strings.TrimSpace(rec.SSHKey)
	if sshKeyEnc != "" && box != nil {
		enc, err := encryptIfPlain(box, sshKeyEnc)
		if err != nil {
			return nil, err
		}
		sshKeyEnc = enc
	}
	_, err := db.ExecContext(ctx, `INSERT INTO sf_project_eve_servers (
  id, project_id, name, api_url, web_url, skip_tls_verify, api_user, api_password, ssh_host, ssh_user, ssh_key, created_at, updated_at
) VALUES ($1,$2,$3,$4,NULLIF($5,''),$6,NULLIF($7,''),NULLIF($8,''),NULLIF($9,''),NULLIF($10,''),NULLIF($11,''),now(),now())
ON CONFLICT (id) DO UPDATE SET
  name=excluded.name,
  api_url=excluded.api_url,
  web_url=excluded.web_url,
  skip_tls_verify=excluded.skip_tls_verify,
  api_user=excluded.api_user,
  api_password=excluded.api_password,
  ssh_host=excluded.ssh_host,
  ssh_user=excluded.ssh_user,
  ssh_key=excluded.ssh_key,
  updated_at=now()`,
		id, rec.OwnerUsername, rec.Name, rec.APIURL, rec.WebURL, rec.SkipTLSVerify, rec.APIUser, passwordEnc, rec.SSHHost, rec.SSHUser, sshKeyEnc,
	)
	if err != nil {
		return nil, err
	}
	out := rec
	out.ID = id
	return &out, nil
}

func deleteOwnerEveServer(ctx context.Context, db *sql.DB, ownerID, id string) error {
	if db == nil {
		return fmt.Errorf("db is not configured")
	}
	ownerID = strings.TrimSpace(ownerID)
	id = strings.TrimSpace(id)
	if ownerID == "" || id == "" {
		return nil
	}
	_, err := db.ExecContext(ctx, `DELETE FROM sf_project_eve_servers WHERE project_id=$1 AND id=$2`, ownerID, id)
	return err
}
