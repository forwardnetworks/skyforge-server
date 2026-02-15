package skyforge

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"encore.dev/beta/errs"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type ForwardOnPremWorkloadStatus struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Ready     int32  `json:"ready"`
	Desired   int32  `json:"desired"`
	Available int32  `json:"available,omitempty"`
}

type ForwardOnPremBackupS3Request struct {
	Enabled       bool   `json:"enabled"`
	Bucket        string `json:"bucket"`
	BucketPrefix  string `json:"bucketPrefix"`
	Region        string `json:"region"`
	Endpoint      string `json:"endpoint"`
	AccessKey     string `json:"accessKey"`
	SecretKey     string `json:"secretKey"`
	RetentionDays int    `json:"retentionDays"`
}

type ForwardOnPremBackupS3Response struct {
	Enabled       bool   `json:"enabled"`
	Bucket        string `json:"bucket"`
	BucketPrefix  string `json:"bucketPrefix"`
	Region        string `json:"region"`
	Endpoint      string `json:"endpoint"`
	RetentionDays int    `json:"retentionDays"`
	HasAccessKey  bool   `json:"hasAccessKey"`
	HasSecretKey  bool   `json:"hasSecretKey"`
	UpdatedAt     string `json:"updatedAt,omitempty"`
	UpdatedBy     string `json:"updatedBy,omitempty"`
	SecretName    string `json:"secretName"`
	Namespace     string `json:"namespace"`
}

type ForwardOnPremStatusResponse struct {
	Namespace         string                        `json:"namespace"`
	ProxyPathPrefix   string                        `json:"proxyPathPrefix"`
	AutosleepEnabled  bool                          `json:"autosleepEnabled"`
	AutosleepIdleMins int                           `json:"autosleepIdleMinutes"`
	Workloads         []ForwardOnPremWorkloadStatus `json:"workloads"`
	Backup            ForwardOnPremBackupS3Response `json:"backup"`
	LatestMetricsAt   string                        `json:"latestMetricsAt,omitempty"`
}

type ForwardOnPremActionResponse struct {
	OK bool   `json:"ok"`
	At string `json:"at,omitempty"`
}

type ForwardOnPremBackupRunItem struct {
	ID          int64   `json:"id"`
	StartedAt   string  `json:"startedAt"`
	CompletedAt string  `json:"completedAt,omitempty"`
	Status      string  `json:"status"`
	Actor       string  `json:"actor,omitempty"`
	Details     JSONMap `json:"details,omitempty"`
}

type ForwardOnPremBackupRunsResponse struct {
	Items []ForwardOnPremBackupRunItem `json:"items"`
}

func forwardOnPremNamespace() string {
	v := strings.TrimSpace(os.Getenv("SKYFORGE_FORWARD_ONPREM_NAMESPACE"))
	if v == "" {
		return "forward"
	}
	return v
}

func forwardOnPremCBRS3Deployment() string {
	v := strings.TrimSpace(os.Getenv("SKYFORGE_FORWARD_ONPREM_CBR_S3_DEPLOYMENT"))
	if v == "" {
		return "fwd-cbr-s3-agent"
	}
	return v
}

func forwardOnPremCBRS3Secret() string {
	v := strings.TrimSpace(os.Getenv("SKYFORGE_FORWARD_ONPREM_CBR_S3_SECRET"))
	if v == "" {
		return "fwd-cbr-s3-config"
	}
	return v
}

func forwardOnPremAutosleepIdleMinutesFromEnv() int {
	v, err := strconv.Atoi(strings.TrimSpace(os.Getenv("SKYFORGE_FORWARD_ONPREM_AUTOSLEEP_IDLE_MINUTES")))
	if err != nil || v <= 0 {
		return 30
	}
	return v
}

func loadForwardOnPremBackupS3Response(ctx context.Context, db *sql.DB, box *secretBox) (ForwardOnPremBackupS3Response, error) {
	resp := ForwardOnPremBackupS3Response{
		Namespace:  forwardOnPremNamespace(),
		SecretName: forwardOnPremCBRS3Secret(),
	}
	if db == nil {
		return resp, sql.ErrConnDone
	}
	cfg, err := getForwardOnPremBackupS3Settings(ctx, db, box)
	if err != nil {
		if isMissingDBRelation(err) {
			return resp, nil
		}
		return resp, err
	}
	if cfg == nil {
		return resp, nil
	}
	resp.Enabled = cfg.Enabled
	resp.Bucket = strings.TrimSpace(cfg.Bucket)
	resp.BucketPrefix = strings.TrimSpace(cfg.BucketPrefix)
	resp.Region = strings.TrimSpace(cfg.Region)
	resp.Endpoint = strings.TrimSpace(cfg.Endpoint)
	resp.RetentionDays = cfg.RetentionDays
	resp.HasAccessKey = strings.TrimSpace(cfg.AccessKey) != ""
	resp.HasSecretKey = strings.TrimSpace(cfg.SecretKey) != ""
	resp.UpdatedBy = strings.TrimSpace(cfg.UpdatedBy)
	if !cfg.UpdatedAt.IsZero() {
		resp.UpdatedAt = cfg.UpdatedAt.UTC().Format(time.RFC3339)
	}
	return resp, nil
}

func upsertEnvValue(vars []corev1.EnvVar, name, value string) []corev1.EnvVar {
	name = strings.TrimSpace(name)
	if name == "" {
		return vars
	}
	for i := range vars {
		if vars[i].Name == name {
			vars[i].Value = value
			vars[i].ValueFrom = nil
			return vars
		}
	}
	return append(vars, corev1.EnvVar{Name: name, Value: value})
}

func upsertEnvSecretRef(vars []corev1.EnvVar, name, secretName, key string) []corev1.EnvVar {
	name = strings.TrimSpace(name)
	secretName = strings.TrimSpace(secretName)
	key = strings.TrimSpace(key)
	if name == "" || secretName == "" || key == "" {
		return vars
	}
	ref := &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: secretName}, Key: key}}
	for i := range vars {
		if vars[i].Name == name {
			vars[i].Value = ""
			vars[i].ValueFrom = ref
			return vars
		}
	}
	return append(vars, corev1.EnvVar{Name: name, ValueFrom: ref})
}

func applyForwardOnPremBackupS3ToKube(ctx context.Context, settings *forwardOnPremBackupS3Settings) error {
	if settings == nil {
		return fmt.Errorf("backup settings required")
	}
	kcfg, err := kubeInClusterConfig()
	if err != nil {
		return err
	}
	clientset, err := kubernetes.NewForConfig(kcfg)
	if err != nil {
		return err
	}
	ns := forwardOnPremNamespace()
	secretName := forwardOnPremCBRS3Secret()
	depName := forwardOnPremCBRS3Deployment()

	secretData := map[string][]byte{
		"AWS_ACCESS_KEY_ID":     []byte(strings.TrimSpace(settings.AccessKey)),
		"AWS_SECRET_ACCESS_KEY": []byte(strings.TrimSpace(settings.SecretKey)),
		"AWS_REGION":            []byte(strings.TrimSpace(settings.Region)),
		"AWS_DEFAULT_REGION":    []byte(strings.TrimSpace(settings.Region)),
		"AWS_ENDPOINT_URL":      []byte(strings.TrimSpace(settings.Endpoint)),
		"CBR_S3_BUCKET":         []byte(strings.TrimSpace(settings.Bucket)),
		"CBR_S3_BUCKET_PREFIX":  []byte(strings.TrimSpace(settings.BucketPrefix)),
		"CBR_RETENTION_DAYS":    []byte(strconv.Itoa(settings.RetentionDays)),
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: secretName, Namespace: ns},
		Type:       corev1.SecretTypeOpaque,
		Data:       secretData,
	}
	if existing, err := clientset.CoreV1().Secrets(ns).Get(ctx, secretName, metav1.GetOptions{}); err == nil && existing != nil {
		existing = existing.DeepCopy()
		existing.Type = corev1.SecretTypeOpaque
		existing.Data = secretData
		if _, err := clientset.CoreV1().Secrets(ns).Update(ctx, existing, metav1.UpdateOptions{}); err != nil {
			return err
		}
	} else {
		if _, err := clientset.CoreV1().Secrets(ns).Create(ctx, secret, metav1.CreateOptions{}); err != nil {
			return err
		}
	}

	dep, err := clientset.AppsV1().Deployments(ns).Get(ctx, depName, metav1.GetOptions{})
	if err != nil {
		return err
	}
	dep = dep.DeepCopy()
	if len(dep.Spec.Template.Spec.Containers) == 0 {
		return fmt.Errorf("deployment %s has no containers", depName)
	}
	idx := 0
	for i := range dep.Spec.Template.Spec.Containers {
		if strings.EqualFold(dep.Spec.Template.Spec.Containers[i].Name, "cbr-agent") {
			idx = i
			break
		}
	}
	vars := dep.Spec.Template.Spec.Containers[idx].Env
	vars = upsertEnvValue(vars, "CBR_AGENT_TYPE", "S3")
	vars = upsertEnvSecretRef(vars, "AWS_ACCESS_KEY_ID", secretName, "AWS_ACCESS_KEY_ID")
	vars = upsertEnvSecretRef(vars, "AWS_SECRET_ACCESS_KEY", secretName, "AWS_SECRET_ACCESS_KEY")
	vars = upsertEnvSecretRef(vars, "AWS_REGION", secretName, "AWS_REGION")
	vars = upsertEnvSecretRef(vars, "AWS_DEFAULT_REGION", secretName, "AWS_DEFAULT_REGION")
	vars = upsertEnvSecretRef(vars, "AWS_ENDPOINT_URL", secretName, "AWS_ENDPOINT_URL")
	vars = upsertEnvSecretRef(vars, "CBR_S3_BUCKET", secretName, "CBR_S3_BUCKET")
	vars = upsertEnvSecretRef(vars, "CBR_S3_BUCKET_PREFIX", secretName, "CBR_S3_BUCKET_PREFIX")
	vars = upsertEnvSecretRef(vars, "CBR_RETENTION_DAYS", secretName, "CBR_RETENTION_DAYS")
	dep.Spec.Template.Spec.Containers[idx].Env = vars

	_, err = clientset.AppsV1().Deployments(ns).Update(ctx, dep, metav1.UpdateOptions{})
	return err
}

func forwardOnPremWorkloadStatus(ctx context.Context) ([]ForwardOnPremWorkloadStatus, error) {
	kcfg, err := kubeInClusterConfig()
	if err != nil {
		return nil, err
	}
	clientset, err := kubernetes.NewForConfig(kcfg)
	if err != nil {
		return nil, err
	}
	ns := forwardOnPremNamespace()
	out := []ForwardOnPremWorkloadStatus{}

	depNames := []string{"fwd-backend-master", "fwd-appserver", "fwd-collector", "fwd-cbr-agent", "fwd-cbr-s3-agent", "fwd-cbr-server"}
	for _, name := range depNames {
		dep, err := clientset.AppsV1().Deployments(ns).Get(ctx, name, metav1.GetOptions{})
		if err != nil || dep == nil {
			continue
		}
		desired := int32(0)
		if dep.Spec.Replicas != nil {
			desired = *dep.Spec.Replicas
		}
		out = append(out, ForwardOnPremWorkloadStatus{
			Kind:      "Deployment",
			Name:      name,
			Ready:     dep.Status.ReadyReplicas,
			Desired:   desired,
			Available: dep.Status.AvailableReplicas,
		})
	}

	stsNames := []string{"fwd-compute-worker", "fwd-search-worker", "fwd-log-aggregator"}
	for _, name := range stsNames {
		sts, err := clientset.AppsV1().StatefulSets(ns).Get(ctx, name, metav1.GetOptions{})
		if err != nil || sts == nil {
			continue
		}
		desired := int32(0)
		if sts.Spec.Replicas != nil {
			desired = *sts.Spec.Replicas
		}
		out = append(out, ForwardOnPremWorkloadStatus{
			Kind:      "StatefulSet",
			Name:      name,
			Ready:     sts.Status.ReadyReplicas,
			Desired:   desired,
			Available: sts.Status.CurrentReplicas,
		})
	}
	return out, nil
}

func latestForwardMetricsCollectedAt(ctx context.Context, db *sql.DB) string {
	if db == nil {
		return ""
	}
	var ts sql.NullTime
	if err := db.QueryRowContext(ctx, `SELECT MAX(collected_at) FROM sf_forward_metrics_snapshots`).Scan(&ts); err != nil {
		return ""
	}
	if !ts.Valid {
		return ""
	}
	return ts.Time.UTC().Format(time.RFC3339)
}

// GetAdminForwardOnPremStatus returns a concise status snapshot for Forward on-prem.
//
//encore:api auth method=GET path=/api/admin/forward/onprem/status tag:admin
func (s *Service) GetAdminForwardOnPremStatus(ctx context.Context) (*ForwardOnPremStatusResponse, error) {
	if _, err := requireAdmin(); err != nil {
		return nil, err
	}
	workloads, _ := forwardOnPremWorkloadStatus(ctx)
	backup, err := loadForwardOnPremBackupS3Response(ctx, s.db, newSecretBox(s.cfg.SessionSecret))
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load backup settings").Err()
	}
	return &ForwardOnPremStatusResponse{
		Namespace:         forwardOnPremNamespace(),
		ProxyPathPrefix:   "/fwd",
		AutosleepEnabled:  forwardOnPremAutosleepEnabled(),
		AutosleepIdleMins: forwardOnPremAutosleepIdleMinutesFromEnv(),
		Workloads:         workloads,
		Backup:            backup,
		LatestMetricsAt:   latestForwardMetricsCollectedAt(ctx, s.db),
	}, nil
}

// GetAdminForwardOnPremBackupS3 returns current stored S3 backup settings (masked).
//
//encore:api auth method=GET path=/api/admin/forward/onprem/backup/s3 tag:admin
func (s *Service) GetAdminForwardOnPremBackupS3(ctx context.Context) (*ForwardOnPremBackupS3Response, error) {
	if _, err := requireAdmin(); err != nil {
		return nil, err
	}
	resp, err := loadForwardOnPremBackupS3Response(ctx, s.db, newSecretBox(s.cfg.SessionSecret))
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load backup settings").Err()
	}
	return &resp, nil
}

// PutAdminForwardOnPremBackupS3 upserts S3 backup settings and reconciles them to Forward workloads.
//
//encore:api auth method=PUT path=/api/admin/forward/onprem/backup/s3 tag:admin
func (s *Service) PutAdminForwardOnPremBackupS3(ctx context.Context, req *ForwardOnPremBackupS3Request) (*ForwardOnPremBackupS3Response, error) {
	user, err := requireAdmin()
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid payload").Err()
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	box := newSecretBox(s.cfg.SessionSecret)

	ctxReq, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	existing, _ := getForwardOnPremBackupS3Settings(ctxReq, s.db, box)

	in := forwardOnPremBackupS3Settings{
		Enabled:       req.Enabled,
		Bucket:        strings.TrimSpace(req.Bucket),
		BucketPrefix:  strings.TrimSpace(req.BucketPrefix),
		Region:        strings.TrimSpace(req.Region),
		Endpoint:      strings.TrimSpace(req.Endpoint),
		AccessKey:     strings.TrimSpace(req.AccessKey),
		SecretKey:     strings.TrimSpace(req.SecretKey),
		RetentionDays: req.RetentionDays,
	}
	if existing != nil {
		if in.AccessKey == "" {
			in.AccessKey = existing.AccessKey
		}
		if in.SecretKey == "" {
			in.SecretKey = existing.SecretKey
		}
		if in.Bucket == "" {
			in.Bucket = existing.Bucket
		}
		if in.BucketPrefix == "" {
			in.BucketPrefix = existing.BucketPrefix
		}
		if in.Region == "" {
			in.Region = existing.Region
		}
		if in.Endpoint == "" {
			in.Endpoint = existing.Endpoint
		}
		if in.RetentionDays <= 0 {
			in.RetentionDays = existing.RetentionDays
		}
	}
	if in.BucketPrefix == "" {
		in.BucketPrefix = "forward/backups"
	}
	if in.RetentionDays <= 0 {
		in.RetentionDays = 30
	}
	if in.Enabled {
		if in.Bucket == "" {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("bucket is required when enabled").Err()
		}
		if in.AccessKey == "" || in.SecretKey == "" {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("accessKey and secretKey are required when enabled").Err()
		}
	}

	runID, _ := appendForwardOnPremBackupRun(ctx, s.db, "running", user.Username, map[string]any{"action": "put"})

	ctxSave, cancelSave := context.WithTimeout(ctx, 10*time.Second)
	defer cancelSave()
	if err := upsertForwardOnPremBackupS3Settings(ctxSave, s.db, box, user.Username, in); err != nil {
		_ = completeForwardOnPremBackupRun(ctx, s.db, runID, "failed", map[string]any{"error": err.Error(), "phase": "store"})
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to save backup settings").Err()
	}

	ctxRecon, cancelRecon := context.WithTimeout(ctx, 40*time.Second)
	defer cancelRecon()
	if err := applyForwardOnPremBackupS3ToKube(ctxRecon, &in); err != nil {
		_ = completeForwardOnPremBackupRun(ctx, s.db, runID, "failed", map[string]any{"error": err.Error(), "phase": "reconcile"})
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to reconcile backup settings to kubernetes").Err()
	}
	_ = completeForwardOnPremBackupRun(ctx, s.db, runID, "ok", map[string]any{"action": "put"})

	resp, err := loadForwardOnPremBackupS3Response(ctx, s.db, box)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load backup settings").Err()
	}
	return &resp, nil
}

// PostAdminForwardOnPremBackupS3Reconcile re-applies stored backup settings to Kubernetes.
//
//encore:api auth method=POST path=/api/admin/forward/onprem/backup/s3/reconcile tag:admin
func (s *Service) PostAdminForwardOnPremBackupS3Reconcile(ctx context.Context) (*ForwardOnPremActionResponse, error) {
	user, err := requireAdmin()
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	box := newSecretBox(s.cfg.SessionSecret)
	cfg, err := getForwardOnPremBackupS3Settings(ctx, s.db, box)
	if err != nil || cfg == nil {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg("backup settings are not configured").Err()
	}
	runID, _ := appendForwardOnPremBackupRun(ctx, s.db, "running", user.Username, map[string]any{"action": "reconcile"})
	ctxReq, cancel := context.WithTimeout(ctx, 40*time.Second)
	defer cancel()
	if err := applyForwardOnPremBackupS3ToKube(ctxReq, cfg); err != nil {
		_ = completeForwardOnPremBackupRun(ctx, s.db, runID, "failed", map[string]any{"error": err.Error(), "action": "reconcile"})
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to reconcile backup settings").Err()
	}
	_ = completeForwardOnPremBackupRun(ctx, s.db, runID, "ok", map[string]any{"action": "reconcile"})
	return &ForwardOnPremActionResponse{OK: true, At: time.Now().UTC().Format(time.RFC3339)}, nil
}

// GetAdminForwardOnPremBackupRuns lists recent backup apply/reconcile run records.
//
//encore:api auth method=GET path=/api/admin/forward/onprem/backup/runs tag:admin
func (s *Service) GetAdminForwardOnPremBackupRuns(ctx context.Context) (*ForwardOnPremBackupRunsResponse, error) {
	if _, err := requireAdmin(); err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	runs, err := listForwardOnPremBackupRuns(ctx, s.db, 25)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load backup runs").Err()
	}
	items := make([]ForwardOnPremBackupRunItem, 0, len(runs))
	for _, r := range runs {
		details, _ := toJSONMap(parseForwardMetricsJSON(r.DetailsJSON))
		item := ForwardOnPremBackupRunItem{
			ID:        r.ID,
			StartedAt: r.StartedAt.UTC().Format(time.RFC3339),
			Status:    r.Status,
			Actor:     r.Actor,
			Details:   details,
		}
		if !r.CompletedAt.IsZero() {
			item.CompletedAt = r.CompletedAt.UTC().Format(time.RFC3339)
		}
		items = append(items, item)
	}
	return &ForwardOnPremBackupRunsResponse{Items: items}, nil
}
