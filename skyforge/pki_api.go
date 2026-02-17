package skyforge

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"log"
	"math/big"
	"net"
	"strings"
	"time"

	"encore.dev/beta/errs"
	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"
)

type PKIRootResponse struct {
	PEM         string `json:"pem"`
	Fingerprint string `json:"fingerprint"`
	Subject     string `json:"subject"`
	NotAfter    string `json:"notAfter"`
}

type PKIIssueRequest struct {
	CommonName    string   `json:"commonName"`
	SANs          []string `json:"sans,omitempty"`
	UserContextID string   `json:"userContextId,omitempty"`
	TTLDays       int      `json:"ttlDays,omitempty"`
}

type PKIIssueResponse struct {
	ID            string `json:"id"`
	CommonName    string `json:"commonName"`
	PEM           string `json:"pem"`
	KeyPEM        string `json:"keyPem"`
	BundlePEM     string `json:"bundlePem"`
	IssuedAt      string `json:"issuedAt"`
	ExpiresAt     string `json:"expiresAt"`
	UserContextID string `json:"userContextId,omitempty"`
	Fingerprint   string `json:"fingerprint"`
}

type PKICertSummary struct {
	ID            string   `json:"id"`
	CommonName    string   `json:"commonName"`
	SANs          []string `json:"sans,omitempty"`
	UserContextID string   `json:"userContextId,omitempty"`
	IssuedAt      string   `json:"issuedAt"`
	ExpiresAt     string   `json:"expiresAt"`
	RevokedAt     string   `json:"revokedAt,omitempty"`
	Fingerprint   string   `json:"fingerprint"`
}

type PKICertsResponse struct {
	Certs []PKICertSummary `json:"certs"`
}

type PKICertDownloadResponse struct {
	ID        string `json:"id"`
	PEM       string `json:"pem"`
	KeyPEM    string `json:"keyPem"`
	BundlePEM string `json:"bundlePem"`
}

type PKISSHRootResponse struct {
	PublicKey   string `json:"publicKey"`
	Fingerprint string `json:"fingerprint"`
	KeyType     string `json:"keyType"`
}

type PKISSHIssueRequest struct {
	Principals    []string `json:"principals,omitempty"`
	UserContextID string   `json:"userContextId,omitempty"`
	TTLDays       int      `json:"ttlDays,omitempty"`
}

type PKISSHIssueResponse struct {
	ID            string   `json:"id"`
	Principals    []string `json:"principals"`
	PublicKey     string   `json:"publicKey"`
	PrivateKey    string   `json:"privateKey"`
	Certificate   string   `json:"certificate"`
	IssuedAt      string   `json:"issuedAt"`
	ExpiresAt     string   `json:"expiresAt"`
	UserContextID string   `json:"userContextId,omitempty"`
	Fingerprint   string   `json:"fingerprint"`
}

type PKISSHCertSummary struct {
	ID            string   `json:"id"`
	Principals    []string `json:"principals"`
	UserContextID string   `json:"userContextId,omitempty"`
	IssuedAt      string   `json:"issuedAt"`
	ExpiresAt     string   `json:"expiresAt"`
	RevokedAt     string   `json:"revokedAt,omitempty"`
	Fingerprint   string   `json:"fingerprint"`
}

type PKISSHCertsResponse struct {
	Certs []PKISSHCertSummary `json:"certs"`
}

type PKISSHCertDownloadResponse struct {
	ID          string `json:"id"`
	PublicKey   string `json:"publicKey"`
	PrivateKey  string `json:"privateKey"`
	Certificate string `json:"certificate"`
}

// GetPKIRoot returns the root CA certificate.
//
//encore:api public method=GET path=/api/pki/root
func (s *Service) GetPKIRoot(ctx context.Context) (*PKIRootResponse, error) {
	certPEM := strings.TrimSpace(s.cfg.PKICACert)
	if certPEM == "" {
		return nil, errs.B().Code(errs.Unavailable).Msg("PKI is not configured").Err()
	}
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, errs.B().Code(errs.Internal).Msg("failed to decode CA cert").Err()
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errs.B().Code(errs.Internal).Msg("failed to parse CA cert").Err()
	}
	fingerprint := sha256.Sum256(block.Bytes)
	_ = ctx
	return &PKIRootResponse{
		PEM:         certPEM,
		Fingerprint: base64.StdEncoding.EncodeToString(fingerprint[:]),
		Subject:     cert.Subject.String(),
		NotAfter:    cert.NotAfter.UTC().Format(time.RFC3339),
	}, nil
}

// IssuePKICert issues a TLS certificate signed by the Skyforge CA.
//
//encore:api auth method=POST path=/api/pki/issue
func (s *Service) IssuePKICert(ctx context.Context, req *PKIIssueRequest) (*PKIIssueResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if s.db == nil || s.box == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	if req == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid payload").Err()
	}
	commonName := strings.TrimSpace(req.CommonName)
	if commonName == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("commonName is required").Err()
	}
	userContextID := strings.TrimSpace(req.UserContextID)
	if userContextID != "" {
		if _, err := s.userContextForUser(user, userContextID); err != nil {
			return nil, err
		}
	}

	caCert, caKey, err := loadPKIConfig(s.cfg)
	if err != nil {
		return nil, err
	}

	ttlDays := s.cfg.PKIDefaultDays
	if req.TTLDays > 0 {
		ttlDays = req.TTLDays
	}
	if ttlDays < 1 || ttlDays > 825 {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("ttlDays must be between 1 and 825").Err()
	}

	now := time.Now().UTC()
	notAfter := now.Add(time.Duration(ttlDays) * 24 * time.Hour)

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, errs.B().Code(errs.Internal).Msg("failed to generate serial").Err()
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, errs.B().Code(errs.Internal).Msg("failed to generate key").Err()
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore: now.Add(-5 * time.Minute),
		NotAfter:  notAfter,
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
	}

	allSANs := normalizeSANs(commonName, req.SANs)
	for _, entry := range allSANs {
		if ip := net.ParseIP(entry); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, entry)
		}
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		return nil, errs.B().Code(errs.Internal).Msg("failed to sign certificate").Err()
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if certPEM == nil || keyPEM == nil {
		return nil, errs.B().Code(errs.Internal).Msg("failed to encode certificate").Err()
	}

	bundle := string(certPEM) + "\n" + strings.TrimSpace(s.cfg.PKICACert) + "\n"
	fingerprint := sha256.Sum256(derBytes)

	encKey, err := encryptIfPlain(s.box, string(keyPEM))
	if err != nil {
		return nil, errs.B().Code(errs.Internal).Msg("failed to encrypt key").Err()
	}
	sansJSON, _ := json.Marshal(allSANs)

	certID := uuid.NewString()
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	_, err = s.db.ExecContext(ctx, `INSERT INTO sf_pki_certs (
  id, username, workspace_id, common_name, sans, cert_pem, key_pem, expires_at
) VALUES ($1,$2,NULLIF($3,''),$4,$5,$6,$7,$8)`,
		certID, strings.ToLower(strings.TrimSpace(user.Username)), userContextID, commonName, sansJSON, string(certPEM), encKey, notAfter)
	if err != nil {
		log.Printf("pki cert insert: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to store certificate").Err()
	}

	return &PKIIssueResponse{
		ID:            certID,
		CommonName:    commonName,
		PEM:           string(certPEM),
		KeyPEM:        string(keyPEM),
		BundlePEM:     bundle,
		IssuedAt:      now.Format(time.RFC3339),
		ExpiresAt:     notAfter.Format(time.RFC3339),
		UserContextID: userContextID,
		Fingerprint:   base64.StdEncoding.EncodeToString(fingerprint[:]),
	}, nil
}

// ListPKICerts lists issued certificates for the current user.
//
//encore:api auth method=GET path=/api/pki/certs
func (s *Service) ListPKICerts(ctx context.Context) (*PKICertsResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	username := strings.ToLower(strings.TrimSpace(user.Username))
	rows, err := s.db.QueryContext(ctx, `SELECT id, common_name, sans, workspace_id, issued_at, expires_at, revoked_at, cert_pem
FROM sf_pki_certs
WHERE username=$1
ORDER BY issued_at DESC`, username)
	if err != nil {
		log.Printf("pki certs list: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to query certificates").Err()
	}
	defer rows.Close()

	certs := make([]PKICertSummary, 0, 32)
	for rows.Next() {
		var (
			id, commonName, certPEM string
			sansRaw                 []byte
			userContextID           sql.NullString
			issuedAt                time.Time
			expiresAt               time.Time
			revokedAt               sql.NullTime
		)
		if err := rows.Scan(&id, &commonName, &sansRaw, &userContextID, &issuedAt, &expiresAt, &revokedAt, &certPEM); err != nil {
			return nil, errs.B().Code(errs.Unavailable).Msg("failed to decode certificates").Err()
		}
		var sans []string
		_ = json.Unmarshal(sansRaw, &sans)
		fingerprint := ""
		if block, _ := pem.Decode([]byte(certPEM)); block != nil {
			fp := sha256.Sum256(block.Bytes)
			fingerprint = base64.StdEncoding.EncodeToString(fp[:])
		}
		entry := PKICertSummary{
			ID:            id,
			CommonName:    commonName,
			SANs:          sans,
			UserContextID: userContextID.String,
			IssuedAt:      issuedAt.UTC().Format(time.RFC3339),
			ExpiresAt:     expiresAt.UTC().Format(time.RFC3339),
			Fingerprint:   fingerprint,
		}
		if revokedAt.Valid {
			entry.RevokedAt = revokedAt.Time.UTC().Format(time.RFC3339)
		}
		certs = append(certs, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to query certificates").Err()
	}
	return &PKICertsResponse{Certs: certs}, nil
}

// DownloadPKICert returns the certificate + key bundle for a specific cert.
//
//encore:api auth method=GET path=/api/pki/certs/:id/download
func (s *Service) DownloadPKICert(ctx context.Context, id string) (*PKICertDownloadResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if s.db == nil || s.box == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("id is required").Err()
	}
	username := strings.ToLower(strings.TrimSpace(user.Username))
	row := s.db.QueryRowContext(ctx, `SELECT cert_pem, key_pem, username FROM sf_pki_certs WHERE id=$1`, id)
	var certPEM, keyEnc, owner string
	if err := row.Scan(&certPEM, &keyEnc, &owner); err != nil {
		return nil, errs.B().Code(errs.NotFound).Msg("certificate not found").Err()
	}
	if !isAdminUser(s.cfg, username) && !strings.EqualFold(owner, username) {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	keyPEM, err := s.box.decrypt(keyEnc)
	if err != nil {
		return nil, errs.B().Code(errs.Internal).Msg("failed to decrypt key").Err()
	}
	bundle := string(certPEM) + "\n" + strings.TrimSpace(s.cfg.PKICACert) + "\n"
	return &PKICertDownloadResponse{
		ID:        id,
		PEM:       certPEM,
		KeyPEM:    keyPEM,
		BundlePEM: bundle,
	}, nil
}

// RevokePKICert marks a certificate revoked.
//
//encore:api auth method=POST path=/api/pki/certs/:id/revoke
func (s *Service) RevokePKICert(ctx context.Context, id string) (*PKICertSummary, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("id is required").Err()
	}
	username := strings.ToLower(strings.TrimSpace(user.Username))
	row := s.db.QueryRowContext(ctx, `SELECT common_name, sans, workspace_id, issued_at, expires_at, revoked_at, cert_pem, username FROM sf_pki_certs WHERE id=$1`, id)
	var (
		commonName, certPEM, owner string
		sansRaw                    []byte
		userContextID              sql.NullString
		issuedAt                   time.Time
		expiresAt                  time.Time
		revokedAt                  sql.NullTime
	)
	if err := row.Scan(&commonName, &sansRaw, &userContextID, &issuedAt, &expiresAt, &revokedAt, &certPEM, &owner); err != nil {
		return nil, errs.B().Code(errs.NotFound).Msg("certificate not found").Err()
	}
	if !isAdminUser(s.cfg, username) && !strings.EqualFold(owner, username) {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	if revokedAt.Valid {
		// already revoked
	} else {
		_, err := s.db.ExecContext(ctx, `UPDATE sf_pki_certs SET revoked_at=now() WHERE id=$1`, id)
		if err != nil {
			log.Printf("pki revoke: %v", err)
			return nil, errs.B().Code(errs.Unavailable).Msg("failed to revoke certificate").Err()
		}
		revokedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}
	}
	var sans []string
	_ = json.Unmarshal(sansRaw, &sans)
	fingerprint := ""
	if block, _ := pem.Decode([]byte(certPEM)); block != nil {
		fp := sha256.Sum256(block.Bytes)
		fingerprint = base64.StdEncoding.EncodeToString(fp[:])
	}
	resp := &PKICertSummary{
		ID:            id,
		CommonName:    commonName,
		SANs:          sans,
		UserContextID: userContextID.String,
		IssuedAt:      issuedAt.UTC().Format(time.RFC3339),
		ExpiresAt:     expiresAt.UTC().Format(time.RFC3339),
		Fingerprint:   fingerprint,
	}
	if revokedAt.Valid {
		resp.RevokedAt = revokedAt.Time.UTC().Format(time.RFC3339)
	}
	return resp, nil
}

// GetPKISSHRoot returns the SSH CA public key.
//
//encore:api auth method=GET path=/api/pki/ssh/root
func (s *Service) GetPKISSHRoot(ctx context.Context) (*PKISSHRootResponse, error) {
	_ = ctx
	signer, pubKey, err := loadSSHCAConfig(s.cfg)
	if err != nil {
		return nil, err
	}
	publicKey := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pubKey)))
	return &PKISSHRootResponse{
		PublicKey:   publicKey,
		Fingerprint: ssh.FingerprintSHA256(pubKey),
		KeyType:     signer.PublicKey().Type(),
	}, nil
}

// IssuePKISSHCert issues an SSH user certificate signed by the Skyforge SSH CA.
//
//encore:api auth method=POST path=/api/pki/ssh/issue
func (s *Service) IssuePKISSHCert(ctx context.Context, req *PKISSHIssueRequest) (*PKISSHIssueResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if s.db == nil || s.box == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	if req == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid payload").Err()
	}
	userContextID := strings.TrimSpace(req.UserContextID)
	if userContextID != "" {
		if _, err := s.userContextForUser(user, userContextID); err != nil {
			return nil, err
		}
	}
	principals := normalizePrincipals(user.Username, req.Principals)
	if len(principals) == 0 {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("principal is required").Err()
	}

	caSigner, _, err := loadSSHCAConfig(s.cfg)
	if err != nil {
		return nil, err
	}

	ttlDays := s.cfg.SSHCADefaultDays
	if req.TTLDays > 0 {
		ttlDays = req.TTLDays
	}
	if ttlDays < 1 || ttlDays > 365 {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("ttlDays must be between 1 and 365").Err()
	}

	now := time.Now().UTC()
	notAfter := now.Add(time.Duration(ttlDays) * 24 * time.Hour)

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, errs.B().Code(errs.Internal).Msg("failed to generate serial").Err()
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, errs.B().Code(errs.Internal).Msg("failed to generate key").Err()
	}
	pubKey, err := ssh.NewPublicKey(&key.PublicKey)
	if err != nil {
		return nil, errs.B().Code(errs.Internal).Msg("failed to generate public key").Err()
	}

	cert := &ssh.Certificate{
		Key:             pubKey,
		Serial:          serial.Uint64(),
		CertType:        ssh.UserCert,
		KeyId:           strings.Join(principals, ","),
		ValidPrincipals: principals,
		ValidAfter:      uint64(now.Add(-2 * time.Minute).Unix()),
		ValidBefore:     uint64(notAfter.Unix()),
		Permissions: ssh.Permissions{
			Extensions: map[string]string{
				"permit-pty":              "",
				"permit-agent-forwarding": "",
				"permit-port-forwarding":  "",
				"permit-user-rc":          "",
				"permit-X11-forwarding":   "",
			},
		},
	}
	if err := cert.SignCert(rand.Reader, caSigner); err != nil {
		return nil, errs.B().Code(errs.Internal).Msg("failed to sign SSH certificate").Err()
	}

	publicKey := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pubKey)))
	certText := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(cert)))
	privateKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if privateKey == nil {
		return nil, errs.B().Code(errs.Internal).Msg("failed to encode SSH key").Err()
	}

	encKey, err := encryptIfPlain(s.box, string(privateKey))
	if err != nil {
		return nil, errs.B().Code(errs.Internal).Msg("failed to encrypt key").Err()
	}
	principalsJSON, _ := json.Marshal(principals)
	certID := uuid.NewString()
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	_, err = s.db.ExecContext(ctx, `INSERT INTO sf_pki_ssh_certs (
  id, username, workspace_id, principals, public_key, cert, key_pem, expires_at
) VALUES ($1,$2,NULLIF($3,''),$4,$5,$6,$7,$8)`,
		certID, strings.ToLower(strings.TrimSpace(user.Username)), userContextID, principalsJSON, publicKey, certText, encKey, notAfter)
	if err != nil {
		log.Printf("pki ssh cert insert: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to store SSH certificate").Err()
	}

	return &PKISSHIssueResponse{
		ID:            certID,
		Principals:    principals,
		PublicKey:     publicKey,
		PrivateKey:    string(privateKey),
		Certificate:   certText,
		IssuedAt:      now.Format(time.RFC3339),
		ExpiresAt:     notAfter.Format(time.RFC3339),
		UserContextID: userContextID,
		Fingerprint:   ssh.FingerprintSHA256(cert),
	}, nil
}

// ListPKISSHCerts lists issued SSH certificates for the current user.
//
//encore:api auth method=GET path=/api/pki/ssh/certs
func (s *Service) ListPKISSHCerts(ctx context.Context) (*PKISSHCertsResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	username := strings.ToLower(strings.TrimSpace(user.Username))
	rows, err := s.db.QueryContext(ctx, `SELECT id, principals, workspace_id, issued_at, expires_at, revoked_at, cert
FROM sf_pki_ssh_certs
WHERE username=$1
ORDER BY issued_at DESC`, username)
	if err != nil {
		log.Printf("pki ssh certs list: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to query SSH certificates").Err()
	}
	defer rows.Close()

	certs := make([]PKISSHCertSummary, 0, 32)
	for rows.Next() {
		var (
			id, certText  string
			principalsRaw []byte
			userContextID sql.NullString
			issuedAt      time.Time
			expiresAt     time.Time
			revokedAt     sql.NullTime
		)
		if err := rows.Scan(&id, &principalsRaw, &userContextID, &issuedAt, &expiresAt, &revokedAt, &certText); err != nil {
			return nil, errs.B().Code(errs.Unavailable).Msg("failed to decode SSH certificates").Err()
		}
		var principals []string
		_ = json.Unmarshal(principalsRaw, &principals)
		fingerprint := ""
		if parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(certText)); err == nil {
			fingerprint = ssh.FingerprintSHA256(parsed)
		}
		entry := PKISSHCertSummary{
			ID:            id,
			Principals:    principals,
			UserContextID: userContextID.String,
			IssuedAt:      issuedAt.UTC().Format(time.RFC3339),
			ExpiresAt:     expiresAt.UTC().Format(time.RFC3339),
			Fingerprint:   fingerprint,
		}
		if revokedAt.Valid {
			entry.RevokedAt = revokedAt.Time.UTC().Format(time.RFC3339)
		}
		certs = append(certs, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to query SSH certificates").Err()
	}
	return &PKISSHCertsResponse{Certs: certs}, nil
}

// DownloadPKISSHCert returns the SSH certificate + key bundle for a specific cert.
//
//encore:api auth method=GET path=/api/pki/ssh/certs/:id/download
func (s *Service) DownloadPKISSHCert(ctx context.Context, id string) (*PKISSHCertDownloadResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if s.db == nil || s.box == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("id is required").Err()
	}
	username := strings.ToLower(strings.TrimSpace(user.Username))
	row := s.db.QueryRowContext(ctx, `SELECT public_key, cert, key_pem, username FROM sf_pki_ssh_certs WHERE id=$1`, id)
	var publicKey, certText, keyEnc, owner string
	if err := row.Scan(&publicKey, &certText, &keyEnc, &owner); err != nil {
		return nil, errs.B().Code(errs.NotFound).Msg("SSH certificate not found").Err()
	}
	if !isAdminUser(s.cfg, username) && !strings.EqualFold(owner, username) {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	keyPEM, err := s.box.decrypt(keyEnc)
	if err != nil {
		return nil, errs.B().Code(errs.Internal).Msg("failed to decrypt key").Err()
	}
	return &PKISSHCertDownloadResponse{
		ID:          id,
		PublicKey:   publicKey,
		PrivateKey:  keyPEM,
		Certificate: certText,
	}, nil
}

// RevokePKISSHCert marks an SSH certificate revoked.
//
//encore:api auth method=POST path=/api/pki/ssh/certs/:id/revoke
func (s *Service) RevokePKISSHCert(ctx context.Context, id string) (*PKISSHCertSummary, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("id is required").Err()
	}
	username := strings.ToLower(strings.TrimSpace(user.Username))
	row := s.db.QueryRowContext(ctx, `SELECT principals, workspace_id, issued_at, expires_at, revoked_at, cert, username FROM sf_pki_ssh_certs WHERE id=$1`, id)
	var (
		principalsRaw []byte
		userContextID sql.NullString
		issuedAt      time.Time
		expiresAt     time.Time
		revokedAt     sql.NullTime
		certText      string
		owner         string
	)
	if err := row.Scan(&principalsRaw, &userContextID, &issuedAt, &expiresAt, &revokedAt, &certText, &owner); err != nil {
		return nil, errs.B().Code(errs.NotFound).Msg("SSH certificate not found").Err()
	}
	if !isAdminUser(s.cfg, username) && !strings.EqualFold(owner, username) {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	if revokedAt.Valid {
		// already revoked
	} else {
		_, err := s.db.ExecContext(ctx, `UPDATE sf_pki_ssh_certs SET revoked_at=now() WHERE id=$1`, id)
		if err != nil {
			log.Printf("pki ssh revoke: %v", err)
			return nil, errs.B().Code(errs.Unavailable).Msg("failed to revoke SSH certificate").Err()
		}
		revokedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}
	}
	var principals []string
	_ = json.Unmarshal(principalsRaw, &principals)
	fingerprint := ""
	if parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(certText)); err == nil {
		fingerprint = ssh.FingerprintSHA256(parsed)
	}
	resp := &PKISSHCertSummary{
		ID:            id,
		Principals:    principals,
		UserContextID: userContextID.String,
		IssuedAt:      issuedAt.UTC().Format(time.RFC3339),
		ExpiresAt:     expiresAt.UTC().Format(time.RFC3339),
		Fingerprint:   fingerprint,
	}
	if revokedAt.Valid {
		resp.RevokedAt = revokedAt.Time.UTC().Format(time.RFC3339)
	}
	return resp, nil
}

func loadPKIConfig(cfg Config) (*x509.Certificate, *rsa.PrivateKey, error) {
	certPEM := strings.TrimSpace(cfg.PKICACert)
	keyPEM := strings.TrimSpace(cfg.PKICAKey)
	if certPEM == "" || keyPEM == "" {
		return nil, nil, errs.B().Code(errs.FailedPrecondition).Msg("PKI is not configured").Err()
	}
	certBlock, _ := pem.Decode([]byte(certPEM))
	if certBlock == nil {
		return nil, nil, errs.B().Code(errs.Internal).Msg("failed to decode CA cert").Err()
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, errs.B().Code(errs.Internal).Msg("failed to parse CA cert").Err()
	}
	keyBlock, _ := pem.Decode([]byte(keyPEM))
	if keyBlock == nil {
		return nil, nil, errs.B().Code(errs.Internal).Msg("failed to decode CA key").Err()
	}
	key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		parsedKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, nil, errs.B().Code(errs.Internal).Msg("failed to parse CA key").Err()
		}
		rsaKey, ok := parsedKey.(*rsa.PrivateKey)
		if !ok {
			return nil, nil, errs.B().Code(errs.Internal).Msg("unsupported CA key type").Err()
		}
		key = rsaKey
	}
	return cert, key, nil
}

func loadSSHCAConfig(cfg Config) (ssh.Signer, ssh.PublicKey, error) {
	keyPEM := strings.TrimSpace(cfg.SSHCAKey)
	if keyPEM == "" {
		return nil, nil, errs.B().Code(errs.FailedPrecondition).Msg("SSH CA is not configured").Err()
	}
	signer, err := ssh.ParsePrivateKey([]byte(keyPEM))
	if err != nil {
		return nil, nil, errs.B().Code(errs.Internal).Msg("failed to parse SSH CA key").Err()
	}
	return signer, signer.PublicKey(), nil
}

func normalizeSANs(commonName string, sans []string) []string {
	seen := map[string]bool{}
	out := []string{}
	add := func(v string) {
		v = strings.TrimSpace(v)
		if v == "" {
			return
		}
		if seen[v] {
			return
		}
		seen[v] = true
		out = append(out, v)
	}
	add(commonName)
	for _, s := range sans {
		add(s)
	}
	return out
}

func normalizePrincipals(defaultPrincipal string, principals []string) []string {
	seen := map[string]bool{}
	out := []string{}
	add := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		value = strings.ToLower(value)
		if seen[value] {
			return
		}
		seen[value] = true
		out = append(out, value)
	}
	add(defaultPrincipal)
	for _, principal := range principals {
		add(principal)
	}
	return out
}
