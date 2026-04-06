package admin

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Service struct {
	store *Store
	log   *log.Logger

	jwtSecret []byte
	accessTTL time.Duration

	refreshTTL       time.Duration
	bootstrapOutFile string
	pgDSN            string
}

type Config struct {
	Store            *Store
	Logger           *log.Logger
	JWTSecret        []byte
	AccessTTL        time.Duration
	RefreshTTL       time.Duration
	BootstrapOutFile string
	PGDSN            string
}

func NewService(cfg Config) (*Service, error) {
	if cfg.Store == nil {
		return nil, fmt.Errorf("admin service: store is required")
	}
	if cfg.Logger == nil {
		cfg.Logger = log.Default()
	}
	if len(cfg.JWTSecret) == 0 {
		tok, err := RandomToken(32)
		if err != nil {
			return nil, err
		}
		cfg.JWTSecret = []byte(tok)
		cfg.Logger.Printf("[admin] ADMIN_JWT_SECRET is empty, generated ephemeral key")
	}
	if cfg.AccessTTL <= 0 {
		cfg.AccessTTL = 15 * time.Minute
	}
	if cfg.RefreshTTL <= 0 {
		cfg.RefreshTTL = 7 * 24 * time.Hour
	}
	if cfg.BootstrapOutFile == "" {
		cfg.BootstrapOutFile = "./admin_bootstrap_credentials.txt"
	}
	return &Service{
		store:            cfg.Store,
		log:              cfg.Logger,
		jwtSecret:        cfg.JWTSecret,
		accessTTL:        cfg.AccessTTL,
		refreshTTL:       cfg.RefreshTTL,
		bootstrapOutFile: cfg.BootstrapOutFile,
		pgDSN:            cfg.PGDSN,
	}, nil
}

func (s *Service) EnsureBootstrapRoot(ctx context.Context) error {
	count, err := s.store.CountAdminUsers(ctx)
	if err != nil {
		return err
	}
	if count > 0 {
		return nil
	}
	login, err := RandomToken(48)
	if err != nil {
		return err
	}
	pass, err := RandomToken(48)
	if err != nil {
		return err
	}
	hash, err := HashPassword(pass)
	if err != nil {
		return err
	}
	_, err = s.store.CreateAdminUser(ctx, login[:64], "root", hash, RoleRoot, false)
	if err != nil {
		return err
	}
	line := fmt.Sprintf("BOOTSTRAP_ROOT_LOGIN=%s\nBOOTSTRAP_ROOT_PASSWORD=%s\n", login[:64], pass)
	s.log.Printf("[admin] bootstrap root created. credentials written to %s", s.bootstrapOutFile)
	if err := os.WriteFile(s.bootstrapOutFile, []byte(line), 0o600); err != nil {
		s.log.Printf("[admin] failed writing bootstrap creds file: %v", err)
	}
	return nil
}

func (s *Service) Login(ctx context.Context, loginName, password, userAgent, remoteIP string) (map[string]any, error) {
	u, hash, err := s.store.GetUserForLogin(ctx, loginName)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("invalid credentials")
		}
		return nil, err
	}
	ok, err := CheckPassword(hash, password)
	if err != nil {
		return nil, err
	}
	if !ok || u.Disabled {
		return nil, fmt.Errorf("invalid credentials")
	}
	accessToken, err := BuildJWT(s.jwtSecret, u.ID, u.Role, s.accessTTL)
	if err != nil {
		return nil, err
	}
	refresh, err := RandomToken(48)
	if err != nil {
		return nil, err
	}
	if err := s.store.InsertSession(ctx, u.ID, refresh, userAgent, remoteIP, time.Now().UTC().Add(s.refreshTTL)); err != nil {
		return nil, err
	}
	_ = s.store.InsertAudit(ctx, u.ID, "auth.login", "session", "", map[string]any{"ip": remoteIP})
	return map[string]any{
		"access_token":          accessToken,
		"refresh_token":         refresh,
		"force_password_change": u.ForcePasswordChange,
		"user":                  u,
	}, nil
}

func (s *Service) Refresh(ctx context.Context, refreshToken string) (map[string]any, error) {
	uid, err := s.store.ValidateSession(ctx, refreshToken)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("invalid refresh token")
		}
		return nil, err
	}
	u, err := s.store.GetUserByID(ctx, uid)
	if err != nil {
		return nil, err
	}
	accessToken, err := BuildJWT(s.jwtSecret, u.ID, u.Role, s.accessTTL)
	if err != nil {
		return nil, err
	}
	return map[string]any{"access_token": accessToken, "user": u}, nil
}

func (s *Service) Logout(ctx context.Context, refreshToken string, actorID int64) error {
	if err := s.store.RevokeSession(ctx, refreshToken); err != nil {
		return err
	}
	_ = s.store.InsertAudit(ctx, actorID, "auth.logout", "session", "", map[string]any{})
	return nil
}

func (s *Service) CreateAdmin(ctx context.Context, actor *AdminUser, loginName, displayName, password string, forcePasswordChange bool) (*AdminUser, error) {
	if actor.Role != RoleRoot {
		return nil, fmt.Errorf("forbidden")
	}
	h, err := HashPassword(password)
	if err != nil {
		return nil, err
	}
	u, err := s.store.CreateAdminUser(ctx, loginName, displayName, h, RoleAdmin, forcePasswordChange)
	if err != nil {
		return nil, err
	}
	_ = s.store.InsertAudit(ctx, actor.ID, "admin.create", "admin_user", strconv.FormatInt(u.ID, 10), u)
	return u, nil
}

func (s *Service) ChangePassword(ctx context.Context, actorID int64, newPassword string, clearForce bool) error {
	h, err := HashPassword(newPassword)
	if err != nil {
		return err
	}
	if err := s.store.UpdateUserPassword(ctx, actorID, h, clearForce); err != nil {
		return err
	}
	_ = s.store.InsertAudit(ctx, actorID, "admin.password_change", "admin_user", strconv.FormatInt(actorID, 10), map[string]any{})
	return nil
}

func (s *Service) ParseAccessToken(token string) (int64, UserRole, error) {
	return ParseAndVerifyJWT(s.jwtSecret, token)
}

func (s *Service) GetUser(ctx context.Context, userID int64) (*AdminUser, error) {
	return s.store.GetUserByID(ctx, userID)
}

func (s *Service) GetNetworkSettings(ctx context.Context) (json.RawMessage, error) {
	return s.store.GetNetworkSettings(ctx)
}

func (s *Service) PutNetworkSettings(ctx context.Context, actorID int64, raw json.RawMessage) error {
	if err := s.store.PutNetworkSettings(ctx, raw); err != nil {
		return err
	}
	_ = s.store.InsertAudit(ctx, actorID, "settings.network.update", "server_settings", "network", json.RawMessage(raw))
	return nil
}

func (s *Service) GetAccessPolicy(ctx context.Context) (*AccessPolicy, error) {
	return s.store.GetAccessPolicy(ctx)
}

func (s *Service) PutAccessPolicy(ctx context.Context, actorID int64, p AccessPolicy) error {
	switch p.Mode {
	case AccessOpen, AccessWhitelist, AccessPassword, AccessKey:
	default:
		return fmt.Errorf("unsupported mode: %s", p.Mode)
	}
	if err := s.store.PutAccessPolicy(ctx, p); err != nil {
		return err
	}
	_ = s.store.InsertAudit(ctx, actorID, "settings.access.update", "access_policy", "1", map[string]any{"mode": p.Mode})
	return nil
}

func (s *Service) GetUsageLimits(ctx context.Context) (*UsageLimits, error) {
	return s.store.GetUsageLimits(ctx)
}

func (s *Service) PutUsageLimits(ctx context.Context, actorID int64, l UsageLimits) error {
	if err := s.store.PutUsageLimits(ctx, l); err != nil {
		return err
	}
	_ = s.store.InsertAudit(ctx, actorID, "limits.update", "usage_limits", "1", l)
	return nil
}

func (s *Service) ListBans(ctx context.Context) ([]BanRule, error) { return s.store.ListBanRules(ctx) }

func (s *Service) AddBan(ctx context.Context, actorID int64, b BanRule) (*BanRule, error) {
	if b.Kind != "username" && b.Kind != "public_key" && b.Kind != "ip" {
		return nil, fmt.Errorf("invalid ban kind")
	}
	out, err := s.store.InsertBanRule(ctx, actorID, b)
	if err != nil {
		return nil, err
	}
	_ = s.store.InsertAudit(ctx, actorID, "ban.add", "ban_rule", strconv.FormatInt(out.ID, 10), out)
	return out, nil
}

func (s *Service) DeleteBan(ctx context.Context, actorID int64, id int64) error {
	if err := s.store.DeleteBanRule(ctx, id); err != nil {
		return err
	}
	_ = s.store.InsertAudit(ctx, actorID, "ban.delete", "ban_rule", strconv.FormatInt(id, 10), map[string]any{})
	return nil
}

func (s *Service) UsageStats(ctx context.Context, limit int) ([]map[string]any, error) {
	return s.store.ListUsageTopByRequests(ctx, limit)
}

func (s *Service) UsersStats(ctx context.Context, limit int) ([]map[string]any, error) {
	return s.store.ListUsageTopByRequests(ctx, limit)
}

func (s *Service) TriggerBackup(ctx context.Context, actorID int64) (int64, error) {
	cfgRaw, err := s.store.GetSetting(ctx, "backups")
	if err != nil {
		return 0, err
	}
	var cfg struct {
		Enabled       bool   `json:"enabled"`
		Directory     string `json:"directory"`
		RetentionDays int    `json:"retention_days"`
	}
	_ = json.Unmarshal(cfgRaw, &cfg)
	if cfg.Directory == "" {
		cfg.Directory = "./backups"
	}
	if cfg.RetentionDays <= 0 {
		cfg.RetentionDays = 7
	}
	if err := os.MkdirAll(cfg.Directory, 0o755); err != nil {
		return 0, err
	}
	jobID, err := s.store.InsertBackupJob(ctx, actorID, cfg.RetentionDays)
	if err != nil {
		return 0, err
	}
	go s.runBackupJob(context.Background(), jobID, cfg.Directory, cfg.RetentionDays)
	_ = s.store.InsertAudit(ctx, actorID, "backup.trigger", "backup_job", strconv.FormatInt(jobID, 10), cfg)
	return jobID, nil
}

func (s *Service) runBackupJob(ctx context.Context, jobID int64, dir string, retentionDays int) {
	_ = s.store.MarkBackupRunning(ctx, jobID)
	stamp := time.Now().UTC().Format("20060102_150405")
	outPath := filepath.Join(dir, fmt.Sprintf("pg_backup_%s.sql", stamp))
	cmd := exec.CommandContext(ctx, "pg_dump", s.pgDSN)
	file, err := os.Create(outPath)
	if err == nil {
		defer file.Close()
		cmd.Stdout = file
		cmd.Stderr = file
		err = cmd.Run()
	}
	_ = s.store.MarkBackupFinished(ctx, jobID, outPath, err)
	if err == nil {
		s.cleanupOldBackups(dir, retentionDays)
	}
}

func (s *Service) cleanupOldBackups(dir string, retentionDays int) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	cutoff := time.Now().UTC().Add(-time.Duration(retentionDays) * 24 * time.Hour)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if !strings.HasPrefix(e.Name(), "pg_backup_") {
			continue
		}
		full := filepath.Join(dir, e.Name())
		st, err := os.Stat(full)
		if err != nil {
			continue
		}
		if st.ModTime().Before(cutoff) {
			_ = os.Remove(full)
		}
	}
}

func (s *Service) ListBackups(ctx context.Context, limit int) ([]BackupJob, error) {
	return s.store.ListBackupJobs(ctx, limit)
}

func (s *Service) RecordNetworkUsage(ctx context.Context, ip, pubkey string, requests, bytesRecv, bytesSent int64, transport, status string) {
	_ = s.store.UpsertClientActivity(ctx, ip, pubkey, requests, bytesRecv, bytesSent, transport, status)
	if ip != "" {
		_ = s.store.IncrementUsageCounters(ctx, "ip", ip, requests, bytesRecv, bytesSent, time.Now().UTC())
	}
	if pubkey != "" {
		_ = s.store.IncrementUsageCounters(ctx, "public_key", pubkey, requests, bytesRecv, bytesSent, time.Now().UTC())
	}
}

func (s *Service) CheckIPAllowed(ctx context.Context, ip string) error {
	if ip == "" {
		return nil
	}
	banned, err := s.store.IsBanned(ctx, "ip", ip)
	if err != nil {
		return err
	}
	if banned {
		return fmt.Errorf("ip banned")
	}
	limits, err := s.store.GetUsageLimits(ctx)
	if err != nil {
		return err
	}
	current, err := s.store.CurrentUsageBySubject(ctx, "ip", ip)
	if err != nil {
		return err
	}
	for bucket, limit := range limits.PerIP {
		if limit <= 0 {
			continue
		}
		v := current[bucket]["requests"]
		if v >= limit {
			return fmt.Errorf("rate limit exceeded: %s", bucket)
		}
	}
	policy, err := s.store.GetAccessPolicy(ctx)
	if err != nil {
		return err
	}
	switch policy.Mode {
	case AccessOpen:
		return nil
	case AccessWhitelist:
		for _, item := range policy.Whitelist {
			if strings.TrimSpace(item) == ip {
				return nil
			}
		}
		return fmt.Errorf("ip is not in whitelist")
	case AccessPassword, AccessKey:
		return fmt.Errorf("server access mode requires gateway auth")
	default:
		return nil
	}
}

func (s *Service) GetMaxRoomParticipants(ctx context.Context) int {
	raw, err := s.store.GetSetting(ctx, "rooms")
	if err != nil {
		return 0
	}
	var cfg struct {
		MaxParticipants int `json:"max_participants"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return 0
	}
	return cfg.MaxParticipants
}

func (s *Service) RunMaintenanceLoop(ctx context.Context, every time.Duration) {
	if every <= 0 {
		every = 1 * time.Hour
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			days, err := s.store.UsernameInactiveDays(ctx)
			if err != nil {
				s.log.Printf("[admin] maintenance: read cleanup settings: %v", err)
				continue
			}
			updated, err := s.store.CleanupInactiveUsernames(ctx, days)
			if err != nil {
				s.log.Printf("[admin] maintenance: cleanup usernames failed: %v", err)
				continue
			}
			if updated > 0 {
				s.log.Printf("[admin] maintenance: cleared %d inactive usernames (threshold=%d days)", updated, days)
			}
		}
	}
}
