package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ════════════════════════════════════════════════════════════════════
// Invite Links
// ════════════════════════════════════════════════════════════════════

func (s *Service) CreateInviteLink(ctx context.Context, actorID int64, ttlHours int) (*InviteLink, error) {
	if ttlHours <= 0 {
		ttlHours = 72
	}
	token, err := RandomToken(32)
	if err != nil {
		return nil, err
	}
	username, err := RandomToken(12)
	if err != nil {
		return nil, err
	}
	generatedUsername := "invite_" + username[:12]
	expiresAt := time.Now().UTC().Add(time.Duration(ttlHours) * time.Hour)

	inv, err := s.store.CreateInviteLink(ctx, token, generatedUsername, expiresAt, actorID)
	if err != nil {
		return nil, err
	}
	_ = s.store.InsertAudit(ctx, actorID, "invite.create", "invite_link", strconv.FormatInt(inv.ID, 10), map[string]any{
		"token":    inv.Token,
		"username": inv.GeneratedUsername,
	})
	return inv, nil
}

func (s *Service) ListInviteLinks(ctx context.Context, limit, offset int) ([]InviteLink, int64, error) {
	return s.store.ListInviteLinks(ctx, limit, offset)
}

func (s *Service) RevokeInviteLink(ctx context.Context, actorID int64, inviteID int64) error {
	inv, err := s.store.GetInviteLinkByID(ctx, inviteID)
	if err != nil {
		return fmt.Errorf("invite not found")
	}
	if inv.Status != "pending" {
		return fmt.Errorf("invite is already %s", inv.Status)
	}
	if err := s.store.RevokeInviteLink(ctx, inviteID); err != nil {
		return err
	}
	_ = s.store.InsertAudit(ctx, actorID, "invite.revoke", "invite_link", strconv.FormatInt(inviteID, 10), map[string]any{})
	return nil
}

func (s *Service) RegisterWithInvite(ctx context.Context, token string, loginName, password string) (*AdminUser, error) {
	inv, err := s.store.GetInviteLinkByToken(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("invalid invite token")
	}
	if inv.Status != "pending" {
		return nil, fmt.Errorf("invite is %s", inv.Status)
	}
	if inv.ExpiresAt.Before(time.Now().UTC()) {
		return nil, fmt.Errorf("invite has expired")
	}

	if strings.TrimSpace(loginName) == "" {
		loginName = inv.GeneratedUsername
	}
	if strings.TrimSpace(password) == "" {
		return nil, fmt.Errorf("password is required")
	}

	h, err := HashPassword(password)
	if err != nil {
		return nil, err
	}
	u, err := s.store.CreateAdminUser(ctx, loginName, loginName, h, RoleAdmin, false)
	if err != nil {
		return nil, err
	}
	if err := s.store.UseInviteLink(ctx, token); err != nil {
		return nil, err
	}
	_ = s.store.InsertAudit(ctx, u.ID, "invite.register", "admin_user", strconv.FormatInt(u.ID, 10), map[string]any{
		"invite_token": token,
	})
	return u, nil
}

// ════════════════════════════════════════════════════════════════════
// User Bans (V7)
// ════════════════════════════════════════════════════════════════════

func (s *Service) BanUser(ctx context.Context, actorID int64, publicKey, reason string, expiresAt *time.Time) (*UserBan, error) {
	publicKey = strings.TrimSpace(publicKey)
	if publicKey == "" {
		return nil, fmt.Errorf("public_key is required")
	}
	actor, err := s.store.GetUserByID(ctx, actorID)
	if err != nil {
		return nil, err
	}
	ban, err := s.store.InsertUserBan(ctx, publicKey, reason, actor.LoginName, expiresAt)
	if err != nil {
		return nil, err
	}
	_ = s.store.InsertAudit(ctx, actorID, "user.ban", "user_ban", publicKey, map[string]any{
		"reason":     reason,
		"expires_at": expiresAt,
	})
	return ban, nil
}

func (s *Service) UnbanUser(ctx context.Context, actorID int64, publicKey, reason string) error {
	publicKey = strings.TrimSpace(publicKey)
	if publicKey == "" {
		return fmt.Errorf("public_key is required")
	}
	actor, err := s.store.GetUserByID(ctx, actorID)
	if err != nil {
		return err
	}
	if err := s.store.UnbanUser(ctx, publicKey, actor.LoginName, reason); err != nil {
		return err
	}
	_ = s.store.InsertAudit(ctx, actorID, "user.unban", "user_ban", publicKey, map[string]any{"reason": reason})
	return nil
}

func (s *Service) ListActiveUserBans(ctx context.Context, limit, offset int) ([]UserBan, int64, error) {
	return s.store.ListActiveUserBans(ctx, limit, offset)
}

func (s *Service) ListUserBanHistory(ctx context.Context, publicKey string) ([]UserBan, error) {
	return s.store.ListUserBansByPubKey(ctx, publicKey)
}

// ════════════════════════════════════════════════════════════════════
// IP Bans (V7)
// ════════════════════════════════════════════════════════════════════

func (s *Service) BanIP(ctx context.Context, actorID int64, ipAddress, reason string, expiresAt *time.Time) (*IPBan, error) {
	ipAddress = strings.TrimSpace(ipAddress)
	if ipAddress == "" {
		return nil, fmt.Errorf("ip_address is required")
	}
	actor, err := s.store.GetUserByID(ctx, actorID)
	if err != nil {
		return nil, err
	}
	ban, err := s.store.InsertIPBan(ctx, ipAddress, reason, actor.LoginName, expiresAt)
	if err != nil {
		return nil, err
	}
	_ = s.store.InsertAudit(ctx, actorID, "ip.ban", "ip_ban", ipAddress, map[string]any{
		"reason":     reason,
		"expires_at": expiresAt,
	})
	return ban, nil
}

func (s *Service) UnbanIP(ctx context.Context, actorID int64, ipAddress, reason string) error {
	ipAddress = strings.TrimSpace(ipAddress)
	if ipAddress == "" {
		return fmt.Errorf("ip_address is required")
	}
	actor, err := s.store.GetUserByID(ctx, actorID)
	if err != nil {
		return err
	}
	if err := s.store.UnbanIP(ctx, ipAddress, actor.LoginName, reason); err != nil {
		return err
	}
	_ = s.store.InsertAudit(ctx, actorID, "ip.unban", "ip_ban", ipAddress, map[string]any{"reason": reason})
	return nil
}

func (s *Service) ListActiveIPBans(ctx context.Context, limit, offset int) ([]IPBan, int64, error) {
	return s.store.ListActiveIPBans(ctx, limit, offset)
}

func (s *Service) ListIPBanHistory(ctx context.Context, ipAddress string) ([]IPBan, error) {
	return s.store.ListIPBanHistory(ctx, ipAddress)
}

// ════════════════════════════════════════════════════════════════════
// Room Bans (V7)
// ════════════════════════════════════════════════════════════════════

func (s *Service) BanRoom(ctx context.Context, actorID int64, roomUUID, reason string, expiresAt *time.Time) (*RoomBan, error) {
	roomUUID = strings.TrimSpace(roomUUID)
	if roomUUID == "" {
		return nil, fmt.Errorf("room_uuid is required")
	}
	actor, err := s.store.GetUserByID(ctx, actorID)
	if err != nil {
		return nil, err
	}
	ban, err := s.store.InsertRoomBan(ctx, roomUUID, reason, actor.LoginName, expiresAt)
	if err != nil {
		return nil, err
	}
	_ = s.store.InsertAudit(ctx, actorID, "room.ban", "room_ban", roomUUID, map[string]any{
		"reason":     reason,
		"expires_at": expiresAt,
	})
	return ban, nil
}

func (s *Service) UnbanRoom(ctx context.Context, actorID int64, roomUUID, reason string) error {
	roomUUID = strings.TrimSpace(roomUUID)
	if roomUUID == "" {
		return fmt.Errorf("room_uuid is required")
	}
	actor, err := s.store.GetUserByID(ctx, actorID)
	if err != nil {
		return err
	}
	if err := s.store.UnbanRoom(ctx, roomUUID, actor.LoginName, reason); err != nil {
		return err
	}
	_ = s.store.InsertAudit(ctx, actorID, "room.unban", "room_ban", roomUUID, map[string]any{"reason": reason})
	return nil
}

func (s *Service) ListActiveRoomBans(ctx context.Context, limit, offset int) ([]RoomBan, int64, error) {
	return s.store.ListActiveRoomBans(ctx, limit, offset)
}

func (s *Service) ListRoomBanHistory(ctx context.Context, roomUUID string) ([]RoomBan, error) {
	return s.store.ListRoomBansByUUID(ctx, roomUUID)
}

// ════════════════════════════════════════════════════════════════════
// User-Room Bans (V7)
// ════════════════════════════════════════════════════════════════════

func (s *Service) BanUserFromRoom(ctx context.Context, actorID int64, publicKey, roomUUID, reason string, expiresAt *time.Time) (*UserRoomBan, error) {
	publicKey = strings.TrimSpace(publicKey)
	roomUUID = strings.TrimSpace(roomUUID)
	if publicKey == "" || roomUUID == "" {
		return nil, fmt.Errorf("public_key and room_uuid are required")
	}
	actor, err := s.store.GetUserByID(ctx, actorID)
	if err != nil {
		return nil, err
	}
	ban, err := s.store.InsertUserRoomBan(ctx, publicKey, roomUUID, reason, actor.LoginName, expiresAt)
	if err != nil {
		return nil, err
	}
	_ = s.store.InsertAudit(ctx, actorID, "user_room.ban", "user_room_ban", publicKey+":"+roomUUID, map[string]any{
		"reason":     reason,
		"expires_at": expiresAt,
	})
	return ban, nil
}

func (s *Service) UnbanUserFromRoom(ctx context.Context, actorID int64, publicKey, roomUUID, reason string) error {
	publicKey = strings.TrimSpace(publicKey)
	roomUUID = strings.TrimSpace(roomUUID)
	if publicKey == "" || roomUUID == "" {
		return fmt.Errorf("public_key and room_uuid are required")
	}
	actor, err := s.store.GetUserByID(ctx, actorID)
	if err != nil {
		return err
	}
	if err := s.store.UnbanUserFromRoom(ctx, publicKey, roomUUID, actor.LoginName, reason); err != nil {
		return err
	}
	_ = s.store.InsertAudit(ctx, actorID, "user_room.unban", "user_room_ban", publicKey+":"+roomUUID, map[string]any{"reason": reason})
	return nil
}

func (s *Service) ListUserRoomBans(ctx context.Context, publicKey string) ([]UserRoomBan, error) {
	return s.store.ListUserRoomBansByPubKey(ctx, publicKey)
}

// ════════════════════════════════════════════════════════════════════
// Bulk Bans
// ════════════════════════════════════════════════════════════════════

func (s *Service) BulkBanUsers(ctx context.Context, actorID int64, publicKeys []string, reason string, expiresAt *time.Time) (int64, error) {
	if len(publicKeys) == 0 {
		return 0, fmt.Errorf("no public keys provided")
	}
	actor, err := s.store.GetUserByID(ctx, actorID)
	if err != nil {
		return 0, err
	}
	count, err := s.store.BulkBanUsers(ctx, publicKeys, reason, actor.LoginName, expiresAt)
	if err != nil {
		return 0, err
	}
	_ = s.store.InsertAudit(ctx, actorID, "user.bulk_ban", "user_ban", "", map[string]any{
		"count":  count,
		"reason": reason,
	})
	return count, nil
}

func (s *Service) BulkUnbanUsers(ctx context.Context, actorID int64, publicKeys []string, reason string) (int64, error) {
	if len(publicKeys) == 0 {
		return 0, fmt.Errorf("no public keys provided")
	}
	actor, err := s.store.GetUserByID(ctx, actorID)
	if err != nil {
		return 0, err
	}
	count, err := s.store.BulkUnbanUsers(ctx, publicKeys, actor.LoginName, reason)
	if err != nil {
		return 0, err
	}
	_ = s.store.InsertAudit(ctx, actorID, "user.bulk_unban", "user_ban", "", map[string]any{
		"count":  count,
		"reason": reason,
	})
	return count, nil
}

func (s *Service) BulkSetUserLimits(ctx context.Context, actorID int64, publicKeys []string, trafficBytes int64, period string, rateLimit int) (int64, error) {
	if len(publicKeys) == 0 {
		return 0, fmt.Errorf("no public keys provided")
	}
	count, err := s.store.BulkPutUserTrafficLimits(ctx, publicKeys, trafficBytes, period, rateLimit)
	if err != nil {
		return 0, err
	}
	_ = s.store.InsertAudit(ctx, actorID, "user.bulk_limits", "user_limits", "", map[string]any{
		"count":                count,
		"traffic_limit_bytes":  trafficBytes,
		"traffic_limit_period": period,
		"request_rate_limit":   rateLimit,
	})
	return count, nil
}

// ════════════════════════════════════════════════════════════════════
// Ban all users in room
// ════════════════════════════════════════════════════════════════════

func (s *Service) BanAllUsersInRoom(ctx context.Context, actorID int64, roomUUID, reason string, expiresAt *time.Time) (int64, error) {
	roomUUID = strings.TrimSpace(roomUUID)
	if roomUUID == "" {
		return 0, fmt.Errorf("room_uuid is required")
	}
	actor, err := s.store.GetUserByID(ctx, actorID)
	if err != nil {
		return 0, err
	}
	count, err := s.store.BanAllUsersInRoom(ctx, roomUUID, reason, actor.LoginName, expiresAt)
	if err != nil {
		return 0, err
	}
	_ = s.store.InsertAudit(ctx, actorID, "room.ban_all_users", "room_ban", roomUUID, map[string]any{
		"count":  count,
		"reason": reason,
	})
	return count, nil
}

// ════════════════════════════════════════════════════════════════════
// Dashboard
// ════════════════════════════════════════════════════════════════════

func (s *Service) GetDashboardMetrics(ctx context.Context) (*DashboardMetrics, error) {
	return s.store.GetDashboardMetrics(ctx)
}

func (s *Service) GetDashboardChart(ctx context.Context, chartType string, days int) ([]map[string]any, error) {
	return s.store.GetDashboardChart(ctx, chartType, days)
}

// ════════════════════════════════════════════════════════════════════
// Sessions
// ════════════════════════════════════════════════════════════════════

func (s *Service) ListActiveSessions(ctx context.Context) ([]map[string]any, error) {
	return s.store.ListActiveSessions(ctx)
}

// ════════════════════════════════════════════════════════════════════
// User Detail Sub-resources
// ════════════════════════════════════════════════════════════════════

func (s *Service) ListUserIPs(ctx context.Context, publicKey string) ([]map[string]any, error) {
	return s.store.ListUserIPs(ctx, publicKey)
}

func (s *Service) ListUserRoomsV1(ctx context.Context, publicKey string) ([]map[string]any, error) {
	return s.store.ListUserRooms(ctx, publicKey)
}

func (s *Service) ChainDetect(ctx context.Context, publicKey string, maxDepth int) ([]map[string]any, error) {
	return s.store.ChainDetect(ctx, publicKey, maxDepth)
}

// ════════════════════════════════════════════════════════════════════
// Room Detail Sub-resources
// ════════════════════════════════════════════════════════════════════

func (s *Service) ListRoomParticipantsV1(ctx context.Context, roomUUID string, limit, offset int) ([]map[string]any, error) {
	return s.store.ListRoomUsers(ctx, roomUUID, "", "", "requests", "desc", limit, offset)
}

func (s *Service) ListRoomParticipantsOnline(ctx context.Context, roomUUID string) ([]map[string]any, error) {
	return s.store.ListRoomParticipantsOnline(ctx, roomUUID, 60)
}

func (s *Service) ListRoomIPs(ctx context.Context, roomUUID string) ([]map[string]any, error) {
	return s.store.ListRoomIPs(ctx, roomUUID)
}

func (s *Service) ListRoomBansV1(ctx context.Context, roomUUID string) ([]UserRoomBan, error) {
	return s.store.ListUserRoomBansByRoom(ctx, roomUUID)
}

// ════════════════════════════════════════════════════════════════════
// User Traffic Limits (per-user on userdir_profiles)
// ════════════════════════════════════════════════════════════════════

func (s *Service) GetUserTrafficLimits(ctx context.Context, publicKey string) (map[string]any, error) {
	return s.store.GetUserTrafficLimits(ctx, publicKey)
}

func (s *Service) PutUserTrafficLimits(ctx context.Context, actorID int64, publicKey string, trafficBytes int64, period string, rateLimit int) error {
	if err := s.store.PutUserTrafficLimits(ctx, publicKey, trafficBytes, period, rateLimit); err != nil {
		return err
	}
	_ = s.store.InsertAudit(ctx, actorID, "user.limits.update", "user_limits", publicKey, map[string]any{
		"traffic_limit_bytes":  trafficBytes,
		"traffic_limit_period": period,
		"request_rate_limit":   rateLimit,
	})
	return nil
}

func (s *Service) DeleteUserTrafficLimits(ctx context.Context, actorID int64, publicKey string) error {
	if err := s.store.DeleteUserTrafficLimits(ctx, publicKey); err != nil {
		return err
	}
	_ = s.store.InsertAudit(ctx, actorID, "user.limits.delete", "user_limits", publicKey, map[string]any{})
	return nil
}

// ════════════════════════════════════════════════════════════════════
// Panel Settings
// ════════════════════════════════════════════════════════════════════

func (s *Service) GetAllPanelSettings(ctx context.Context) (map[string]json.RawMessage, error) {
	return s.store.GetAllPanelSettings(ctx)
}

func (s *Service) PatchPanelSettings(ctx context.Context, actorID int64, updates map[string]json.RawMessage) error {
	for key, value := range updates {
		if err := s.store.PutPanelSetting(ctx, key, value); err != nil {
			return err
		}
	}
	_ = s.store.InsertAudit(ctx, actorID, "settings.panel.update", "admin_panel_settings", "", updates)
	return nil
}

// ════════════════════════════════════════════════════════════════════
// Trusted IPs
// ════════════════════════════════════════════════════════════════════

func (s *Service) ListTrustedIPs(ctx context.Context) ([]TrustedIP, error) {
	return s.store.ListTrustedIPs(ctx)
}

func (s *Service) AddTrustedIP(ctx context.Context, actorID int64, ip string) (*TrustedIP, error) {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return nil, fmt.Errorf("ip_address is required")
	}
	actor, err := s.store.GetUserByID(ctx, actorID)
	if err != nil {
		return nil, err
	}
	t, err := s.store.AddTrustedIP(ctx, ip, actor.LoginName)
	if err != nil {
		return nil, err
	}
	_ = s.store.InsertAudit(ctx, actorID, "trusted_ip.add", "trusted_ip", ip, map[string]any{})
	return t, nil
}

func (s *Service) DeleteTrustedIP(ctx context.Context, actorID int64, ip string) error {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return fmt.Errorf("ip_address is required")
	}
	if err := s.store.DeleteTrustedIP(ctx, ip); err != nil {
		return err
	}
	_ = s.store.InsertAudit(ctx, actorID, "trusted_ip.delete", "trusted_ip", ip, map[string]any{})
	return nil
}

// ════════════════════════════════════════════════════════════════════
// Backup Settings
// ════════════════════════════════════════════════════════════════════

func (s *Service) GetBackupSettings(ctx context.Context) (*BackupSettings, error) {
	return s.store.GetBackupSettings(ctx)
}

func (s *Service) PutBackupSettings(ctx context.Context, actorID int64, bs BackupSettings) error {
	if err := s.store.PutBackupSettings(ctx, bs); err != nil {
		return err
	}
	_ = s.store.InsertAudit(ctx, actorID, "backup.settings.update", "backup_settings", "1", bs)
	return nil
}

func (s *Service) DeleteBackupJob(ctx context.Context, actorID int64, jobID int64) error {
	if err := s.store.DeleteBackupJob(ctx, jobID); err != nil {
		return err
	}
	_ = s.store.InsertAudit(ctx, actorID, "backup.delete", "backup_job", strconv.FormatInt(jobID, 10), map[string]any{})
	return nil
}

// ════════════════════════════════════════════════════════════════════
// Audit Log (scoped)
// ════════════════════════════════════════════════════════════════════

func (s *Service) ListAuditLog(ctx context.Context, objectType, objectID, actionLike string, limit, offset int) ([]map[string]any, int64, error) {
	return s.store.ListAuditLog(ctx, objectType, objectID, actionLike, limit, offset)
}

// ════════════════════════════════════════════════════════════════════
// Admin Deactivate by username
// ════════════════════════════════════════════════════════════════════

func (s *Service) DeactivateAdminByUsername(ctx context.Context, actor *AdminUser, username string) error {
	target, err := s.store.GetAdminUserByUsername(ctx, username)
	if err != nil {
		return fmt.Errorf("admin user not found: %s", username)
	}
	return s.SetAdminDisabled(ctx, actor, target.ID, true)
}

// ════════════════════════════════════════════════════════════════════
// Export
// ════════════════════════════════════════════════════════════════════

// ExportData triggers a full data export (same mechanism as backup but returns the path).
func (s *Service) ExportData(ctx context.Context, actorID int64) (int64, error) {
	jobID, err := s.TriggerBackup(ctx, actorID)
	if err != nil {
		return 0, err
	}
	_ = s.store.InsertAudit(ctx, actorID, "export.trigger", "export", strconv.FormatInt(jobID, 10), map[string]any{})
	return jobID, nil
}

// ════════════════════════════════════════════════════════════════════
// Paginated Users and Rooms (with total count)
// ════════════════════════════════════════════════════════════════════

func (s *Service) ListUsersPaginated(ctx context.Context, search, ipFilter, pubFilter, sortBy, sortOrder string, page, perPage int) ([]map[string]any, int64, error) {
	if page <= 0 {
		page = 1
	}
	if perPage <= 0 {
		perPage = 50
	}
	if perPage > 500 {
		perPage = 500
	}
	offset := (page - 1) * perPage

	total, err := s.store.CountUsersDetailed(ctx, search, ipFilter, pubFilter)
	if err != nil {
		return nil, 0, err
	}

	items, err := s.store.ListUsersDetailed(ctx, search, ipFilter, pubFilter, sortBy, sortOrder, perPage, offset)
	if err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

func (s *Service) ListRoomsPaginated(ctx context.Context, search, sortBy, sortOrder string, page, perPage int) ([]map[string]any, int64, error) {
	if page <= 0 {
		page = 1
	}
	if perPage <= 0 {
		perPage = 50
	}
	if perPage > 500 {
		perPage = 500
	}
	offset := (page - 1) * perPage

	total, err := s.store.CountRoomsDetailed(ctx, search)
	if err != nil {
		return nil, 0, err
	}

	items, err := s.store.ListRoomsDetailed(ctx, search, sortBy, sortOrder, perPage, offset)
	if err != nil {
		return nil, 0, err
	}
	return items, total, nil
}
