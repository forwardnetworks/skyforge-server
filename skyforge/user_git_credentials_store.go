package skyforge

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

type userGitCredentials struct {
	Username      string
	SSHPublicKey  string
	SSHPrivateKey string
	HTTPSUsername string
	HTTPSToken    string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

func getUserGitCredentials(ctx context.Context, db *sql.DB, box *secretBox, username string) (*userGitCredentials, error) {
	if db == nil {
		return nil, fmt.Errorf("db is not configured")
	}
	username = strings.TrimSpace(username)
	if username == "" {
		return nil, fmt.Errorf("username is required")
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	var rec userGitCredentials
	var pub, privEnc, httpsUser, httpsTokenEnc sql.NullString
	if err := db.QueryRowContext(ctx, `
SELECT username, COALESCE(ssh_public_key,''), COALESCE(ssh_private_key,''), COALESCE(https_username,''), COALESCE(https_token,''), created_at, updated_at
FROM sf_user_git_credentials
WHERE username=$1
`, username).Scan(&rec.Username, &pub, &privEnc, &httpsUser, &httpsTokenEnc, &rec.CreatedAt, &rec.UpdatedAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	rec.SSHPublicKey = strings.TrimSpace(pub.String)
	priv := strings.TrimSpace(privEnc.String)
	if priv != "" && box != nil {
		if decrypted, err := box.decrypt(priv); err == nil {
			priv = strings.TrimSpace(decrypted)
		}
	}
	rec.SSHPrivateKey = priv
	rec.HTTPSUsername = strings.TrimSpace(httpsUser.String)
	token := strings.TrimSpace(httpsTokenEnc.String)
	if token != "" && box != nil {
		if decrypted, err := box.decrypt(token); err == nil {
			token = strings.TrimSpace(decrypted)
		}
	}
	rec.HTTPSToken = token
	return &rec, nil
}

func upsertUserGitCredentials(ctx context.Context, db *sql.DB, box *secretBox, rec userGitCredentials) (*userGitCredentials, error) {
	if db == nil {
		return nil, fmt.Errorf("db is not configured")
	}
	rec.Username = strings.TrimSpace(rec.Username)
	rec.SSHPublicKey = strings.TrimSpace(rec.SSHPublicKey)
	rec.SSHPrivateKey = strings.TrimSpace(rec.SSHPrivateKey)
	rec.HTTPSUsername = strings.TrimSpace(rec.HTTPSUsername)
	rec.HTTPSToken = strings.TrimSpace(rec.HTTPSToken)
	if rec.Username == "" {
		return nil, fmt.Errorf("username is required")
	}

	privateEnc := strings.TrimSpace(rec.SSHPrivateKey)
	if privateEnc != "" && box != nil {
		enc, err := encryptIfPlain(box, privateEnc)
		if err != nil {
			return nil, err
		}
		privateEnc = enc
	}
	tokenEnc := strings.TrimSpace(rec.HTTPSToken)
	if tokenEnc != "" && box != nil {
		enc, err := encryptIfPlain(box, tokenEnc)
		if err != nil {
			return nil, err
		}
		tokenEnc = enc
	}

	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	_, err := db.ExecContext(ctx, `
INSERT INTO sf_user_git_credentials (username, ssh_public_key, ssh_private_key, https_username, https_token, created_at, updated_at)
VALUES ($1,NULLIF($2,''),NULLIF($3,''),NULLIF($4,''),NULLIF($5,''),now(),now())
ON CONFLICT (username) DO UPDATE SET
  ssh_public_key=excluded.ssh_public_key,
  ssh_private_key=excluded.ssh_private_key,
  https_username=excluded.https_username,
  https_token=excluded.https_token,
  updated_at=now()
`, rec.Username, rec.SSHPublicKey, privateEnc, rec.HTTPSUsername, tokenEnc)
	if err != nil {
		return nil, err
	}

	out := rec
	return &out, nil
}

func ensureUserGitDeployKey(ctx context.Context, db *sql.DB, box *secretBox, username string) (*userGitCredentials, error) {
	if db == nil {
		return nil, fmt.Errorf("db is not configured")
	}
	username = strings.TrimSpace(username)
	if username == "" {
		return nil, fmt.Errorf("username is required")
	}
	if box == nil {
		return nil, fmt.Errorf("secret box unavailable")
	}

	existing, err := getUserGitCredentials(ctx, db, box, username)
	if err != nil {
		return nil, err
	}
	if existing != nil && strings.TrimSpace(existing.SSHPublicKey) != "" && strings.TrimSpace(existing.SSHPrivateKey) != "" {
		return existing, nil
	}
	if existing == nil {
		existing = &userGitCredentials{Username: username}
	}

	key, err := generateEd25519Keypair()
	if err != nil {
		return nil, err
	}
	existing.SSHPrivateKey = key.PrivatePEM
	existing.SSHPublicKey = strings.TrimSpace(key.PublicAuthorizedKey)

	return upsertUserGitCredentials(ctx, db, box, *existing)
}

type generatedSSHKeypair struct {
	PrivatePEM          string
	PublicAuthorizedKey string
}

func generateSSHPrivateKeyPEMEd25519() (string, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	raw, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", err
	}
	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: raw,
	}
	return string(pem.EncodeToMemory(block)), nil
}

func generateEd25519Keypair() (*generatedSSHKeypair, error) {
	privKey, err := generateSSHPrivateKeyPEMEd25519()
	if err != nil {
		return nil, err
	}
	signer, err := ssh.ParsePrivateKey([]byte(privKey))
	if err != nil {
		return nil, err
	}
	pub := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	return &generatedSSHKeypair{
		PrivatePEM:          privKey,
		PublicAuthorizedKey: pub,
	}, nil
}
