package admin

import (
	"context"
	"encoding/json"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// APIV1Handler serves the /api/v1/ routes. It reuses the same Service and
// authentication middleware as the existing admin HTTPHandler.
type APIV1Handler struct {
	svc *Service
}

// NewAPIV1Handler creates a new handler for the v1 REST API.
func NewAPIV1Handler(svc *Service) *APIV1Handler {
	return &APIV1Handler{svc: svc}
}

// Register wires every /api/v1/* route onto the given mux.
func (h *APIV1Handler) Register(mux *http.ServeMux) {
	// ── Auth ──────────────────────────────────────────────────────
	mux.HandleFunc("POST /api/v1/auth/login", h.handleLogin)
	mux.HandleFunc("POST /api/v1/auth/logout", h.requireAuth(h.handleLogout))
	mux.HandleFunc("GET /api/v1/auth/me", h.requireAuth(h.handleMe))

	// ── Invites ──────────────────────────────────────────────────
	mux.HandleFunc("GET /api/v1/invites", h.requireAuth(h.handleListInvites))
	mux.HandleFunc("POST /api/v1/invites", h.requireAuth(h.handleCreateInvite))
	mux.HandleFunc("POST /api/v1/invites/{id}/revoke", h.requireAuth(h.handleRevokeInvite))
	mux.HandleFunc("POST /api/v1/invites/{token}/register", h.handleRegisterWithInvite)

	// ── Admins ───────────────────────────────────────────────────
	mux.HandleFunc("GET /api/v1/admins", h.requireAuth(h.handleListAdmins))
	mux.HandleFunc("POST /api/v1/admins/{username}/deactivate", h.requireAuth(h.handleDeactivateAdmin))

	// ── Sessions ─────────────────────────────────────────────────
	mux.HandleFunc("GET /api/v1/sessions", h.requireAuth(h.handleListSessions))

	// ── Dashboard ────────────────────────────────────────────────
	mux.HandleFunc("GET /api/v1/dashboard/metrics", h.requireAuth(h.handleDashboardMetrics))
	mux.HandleFunc("GET /api/v1/dashboard/charts/{chart_type}", h.requireAuth(h.handleDashboardChart))

	// ── Users ────────────────────────────────────────────────────
	mux.HandleFunc("GET /api/v1/users", h.requireAuth(h.handleListUsers))
	mux.HandleFunc("GET /api/v1/users/{public_key}", h.requireAuth(h.handleGetUser))
	mux.HandleFunc("GET /api/v1/users/{public_key}/ips", h.requireAuth(h.handleUserIPs))
	mux.HandleFunc("GET /api/v1/users/{public_key}/rooms", h.requireAuth(h.handleUserRooms))
	mux.HandleFunc("GET /api/v1/users/{public_key}/chain", h.requireAuth(h.handleUserChain))
	mux.HandleFunc("GET /api/v1/users/{public_key}/bans", h.requireAuth(h.handleUserBans))
	mux.HandleFunc("POST /api/v1/users/{public_key}/ban", h.requireAuth(h.handleBanUser))
	mux.HandleFunc("POST /api/v1/users/{public_key}/unban", h.requireAuth(h.handleUnbanUser))
	mux.HandleFunc("GET /api/v1/users/{public_key}/room-bans", h.requireAuth(h.handleUserRoomBans))
	mux.HandleFunc("POST /api/v1/users/{public_key}/rooms/{room_uuid}/ban", h.requireAuth(h.handleBanUserFromRoom))
	mux.HandleFunc("POST /api/v1/users/{public_key}/rooms/{room_uuid}/unban", h.requireAuth(h.handleUnbanUserFromRoom))
	mux.HandleFunc("PUT /api/v1/users/{public_key}/limits", h.requireAuth(h.handlePutUserLimits))
	mux.HandleFunc("DELETE /api/v1/users/{public_key}/limits", h.requireAuth(h.handleDeleteUserLimits))
	mux.HandleFunc("GET /api/v1/users/{public_key}/audit-log", h.requireAuth(h.handleUserAuditLog))

	// ── Bulk User Operations ─────────────────────────────────────
	mux.HandleFunc("POST /api/v1/users/bulk/ban", h.requireAuth(h.handleBulkBanUsers))
	mux.HandleFunc("POST /api/v1/users/bulk/unban", h.requireAuth(h.handleBulkUnbanUsers))
	mux.HandleFunc("PUT /api/v1/users/bulk/limits", h.requireAuth(h.handleBulkSetLimits))

	// ── Bans ─────────────────────────────────────────────────────
	mux.HandleFunc("GET /api/v1/bans/users", h.requireAuth(h.handleListUserBans))
	mux.HandleFunc("GET /api/v1/bans/ips", h.requireAuth(h.handleListIPBans))
	mux.HandleFunc("POST /api/v1/bans/ips", h.requireAuth(h.handleBanIP))
	mux.HandleFunc("GET /api/v1/bans/ips/{ip_address}/history", h.requireAuth(h.handleIPBanHistory))
	mux.HandleFunc("POST /api/v1/bans/ips/{ip_address}/unban", h.requireAuth(h.handleUnbanIP))
	mux.HandleFunc("GET /api/v1/bans/rooms", h.requireAuth(h.handleListRoomBans))

	// ── Rooms ────────────────────────────────────────────────────
	mux.HandleFunc("GET /api/v1/rooms", h.requireAuth(h.handleListRooms))
	mux.HandleFunc("GET /api/v1/rooms/{uuid}", h.requireAuth(h.handleGetRoom))
	mux.HandleFunc("GET /api/v1/rooms/{uuid}/participants", h.requireAuth(h.handleRoomParticipants))
	mux.HandleFunc("GET /api/v1/rooms/{uuid}/participants/online", h.requireAuth(h.handleRoomParticipantsOnline))
	mux.HandleFunc("GET /api/v1/rooms/{uuid}/ips", h.requireAuth(h.handleRoomIPs))
	mux.HandleFunc("GET /api/v1/rooms/{uuid}/bans", h.requireAuth(h.handleRoomBansDetail))
	mux.HandleFunc("POST /api/v1/rooms/{uuid}/ban", h.requireAuth(h.handleBanRoom))
	mux.HandleFunc("POST /api/v1/rooms/{uuid}/unban", h.requireAuth(h.handleUnbanRoom))
	mux.HandleFunc("POST /api/v1/rooms/{uuid}/ban-all-users", h.requireAuth(h.handleBanAllUsersInRoom))
	mux.HandleFunc("GET /api/v1/rooms/{uuid}/audit-log", h.requireAuth(h.handleRoomAuditLog))

	// ── Audit Log ────────────────────────────────────────────────
	mux.HandleFunc("GET /api/v1/audit-log", h.requireAuth(h.handleAuditLog))

	// ── Settings ─────────────────────────────────────────────────
	mux.HandleFunc("GET /api/v1/settings", h.requireAuth(h.handleGetSettings))
	mux.HandleFunc("PATCH /api/v1/settings", h.requireAuth(h.handlePatchSettings))
	mux.HandleFunc("GET /api/v1/settings/trusted-ips", h.requireAuth(h.handleListTrustedIPs))
	mux.HandleFunc("POST /api/v1/settings/trusted-ips", h.requireAuth(h.handleAddTrustedIP))
	mux.HandleFunc("DELETE /api/v1/settings/trusted-ips/{ip}", h.requireAuth(h.handleDeleteTrustedIP))

	// ── Backups ──────────────────────────────────────────────────
	mux.HandleFunc("GET /api/v1/backups", h.requireAuth(h.handleListBackups))
	mux.HandleFunc("POST /api/v1/backups/now", h.requireAuth(h.handleTriggerBackup))
	mux.HandleFunc("DELETE /api/v1/backups/{id}", h.requireAuth(h.handleDeleteBackup))
	mux.HandleFunc("GET /api/v1/backups/settings", h.requireAuth(h.handleGetBackupSettings))
	mux.HandleFunc("PUT /api/v1/backups/settings", h.requireAuth(h.handlePutBackupSettings))

	// ── Export ───────────────────────────────────────────────────
	mux.HandleFunc("POST /api/v1/export", h.requireAuth(h.handleExport))
}

// ════════════════════════════════════════════════════════════════════
// Auth middleware — supports both Bearer token and session_id cookie
// ════════════════════════════════════════════════════════════════════

func (h *APIV1Handler) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var uid int64
		var err error

		// Try Bearer token first.
		if hdr := r.Header.Get("Authorization"); hdr != "" {
			parts := strings.SplitN(hdr, " ", 2)
			if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
				uid, _, err = h.svc.ParseAccessToken(parts[1])
				if err != nil {
					writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid or expired token"})
					return
				}
			}
		}

		// Fall back to session_id cookie.
		if uid == 0 {
			cookie, cerr := r.Cookie("session_id")
			if cerr == nil && cookie.Value != "" {
				uid, err = h.svc.store.ValidateSession(r.Context(), cookie.Value)
				if err != nil {
					writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid session"})
					return
				}
			}
		}

		if uid == 0 {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
			return
		}

		u, err := h.svc.GetUser(r.Context(), uid)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "user not found"})
			return
		}

		ctx := setUserCtx(r.Context(), u)
		next(w, r.WithContext(ctx))
	}
}

// ════════════════════════════════════════════════════════════════════
// Auth handlers
// ════════════════════════════════════════════════════════════════════

func (h *APIV1Handler) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		LoginName string `json:"login_name"`
		Password  string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid request body"})
		return
	}
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	res, err := h.svc.Login(r.Context(), req.LoginName, req.Password, r.UserAgent(), ip)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid credentials"})
		return
	}

	// Set session cookie with refresh token for cookie-based auth.
	if rt, ok := res["refresh_token"].(string); ok {
		http.SetCookie(w, &http.Cookie{
			Name:     "session_id",
			Value:    rt,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   7 * 24 * 60 * 60,
		})
	}
	writeJSON(w, http.StatusOK, res)
}

func (h *APIV1Handler) handleLogout(w http.ResponseWriter, r *http.Request) {
	u := userFromCtx(r.Context())
	if u == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	// Also check cookie
	if req.RefreshToken == "" {
		if c, err := r.Cookie("session_id"); err == nil {
			req.RefreshToken = c.Value
		}
	}
	if req.RefreshToken != "" {
		_ = h.svc.Logout(r.Context(), req.RefreshToken, u.ID)
	}

	// Clear cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (h *APIV1Handler) handleMe(w http.ResponseWriter, r *http.Request) {
	u := userFromCtx(r.Context())
	if u == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	writeJSON(w, http.StatusOK, u)
}

// ════════════════════════════════════════════════════════════════════
// Invites
// ════════════════════════════════════════════════════════════════════

func (h *APIV1Handler) handleListInvites(w http.ResponseWriter, r *http.Request) {
	page, perPage := parsePagination(r)
	invites, total, err := h.svc.ListInviteLinks(r.Context(), perPage, (page-1)*perPage)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writePaginatedJSON(w, invites, total, page, perPage)
}

func (h *APIV1Handler) handleCreateInvite(w http.ResponseWriter, r *http.Request) {
	u := userFromCtx(r.Context())
	var req struct {
		TTLHours int `json:"ttl_hours"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	inv, err := h.svc.CreateInviteLink(r.Context(), u.ID, req.TTLHours)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, inv)
}

func (h *APIV1Handler) handleRevokeInvite(w http.ResponseWriter, r *http.Request) {
	u := userFromCtx(r.Context())
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid invite id"})
		return
	}
	if err := h.svc.RevokeInviteLink(r.Context(), u.ID, id); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (h *APIV1Handler) handleRegisterWithInvite(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	if token == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "token is required"})
		return
	}
	var req struct {
		LoginName string `json:"login_name"`
		Password  string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid request body"})
		return
	}
	user, err := h.svc.RegisterWithInvite(r.Context(), token, req.LoginName, req.Password)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, user)
}

// ════════════════════════════════════════════════════════════════════
// Admins
// ════════════════════════════════════════════════════════════════════

func (h *APIV1Handler) handleListAdmins(w http.ResponseWriter, r *http.Request) {
	admins, err := h.svc.ListAdmins(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"data": admins,
		"meta": map[string]any{"total": len(admins)},
	})
}

func (h *APIV1Handler) handleDeactivateAdmin(w http.ResponseWriter, r *http.Request) {
	actor := userFromCtx(r.Context())
	username := r.PathValue("username")
	if username == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "username is required"})
		return
	}
	if err := h.svc.DeactivateAdminByUsername(r.Context(), actor, username); err != nil {
		code := http.StatusBadRequest
		if strings.Contains(strings.ToLower(err.Error()), "forbidden") {
			code = http.StatusForbidden
		}
		writeJSON(w, code, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ════════════════════════════════════════════════════════════════════
// Sessions
// ════════════════════════════════════════════════════════════════════

func (h *APIV1Handler) handleListSessions(w http.ResponseWriter, r *http.Request) {
	sessions, err := h.svc.ListActiveSessions(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"data": sessions,
		"meta": map[string]any{"total": len(sessions)},
	})
}

// ════════════════════════════════════════════════════════════════════
// Dashboard
// ════════════════════════════════════════════════════════════════════

func (h *APIV1Handler) handleDashboardMetrics(w http.ResponseWriter, r *http.Request) {
	metrics, err := h.svc.GetDashboardMetrics(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, metrics)
}

func (h *APIV1Handler) handleDashboardChart(w http.ResponseWriter, r *http.Request) {
	chartType := r.PathValue("chart_type")
	days, _ := strconv.Atoi(r.URL.Query().Get("days"))
	if days <= 0 {
		days = 30
	}
	data, err := h.svc.GetDashboardChart(r.Context(), chartType, days)
	if err != nil {
		code := http.StatusInternalServerError
		if strings.Contains(err.Error(), "unknown chart type") {
			code = http.StatusBadRequest
		}
		writeJSON(w, code, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"chart_type": chartType,
		"days":       days,
		"data":       data,
	})
}

// ════════════════════════════════════════════════════════════════════
// Users
// ════════════════════════════════════════════════════════════════════

func (h *APIV1Handler) handleListUsers(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	page, perPage := parsePagination(r)
	search := q.Get("search")
	ipFilter := q.Get("ip")
	pubFilter := q.Get("public_key")
	sortBy := q.Get("sort")
	order := q.Get("order")

	items, total, err := h.svc.ListUsersPaginated(r.Context(), search, ipFilter, pubFilter, sortBy, order, page, perPage)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writePaginatedJSON(w, items, total, page, perPage)
}

func (h *APIV1Handler) handleGetUser(w http.ResponseWriter, r *http.Request) {
	publicKey := r.PathValue("public_key")
	if publicKey == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "public_key is required"})
		return
	}
	info, err := h.svc.GetUserDetails(r.Context(), publicKey)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "user not found"})
		return
	}
	// Enrich with ban status
	banned, _ := h.svc.store.IsUserBanned(r.Context(), publicKey)
	info["is_banned"] = banned

	// Enrich with per-user limits
	limits, lerr := h.svc.GetUserTrafficLimits(r.Context(), publicKey)
	if lerr == nil {
		info["limits"] = limits
	}
	writeJSON(w, http.StatusOK, info)
}

func (h *APIV1Handler) handleUserIPs(w http.ResponseWriter, r *http.Request) {
	publicKey := r.PathValue("public_key")
	ips, err := h.svc.ListUserIPs(r.Context(), publicKey)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": ips})
}

func (h *APIV1Handler) handleUserRooms(w http.ResponseWriter, r *http.Request) {
	publicKey := r.PathValue("public_key")
	rooms, err := h.svc.ListUserRoomsV1(r.Context(), publicKey)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": rooms})
}

func (h *APIV1Handler) handleUserChain(w http.ResponseWriter, r *http.Request) {
	publicKey := r.PathValue("public_key")
	depth, _ := strconv.Atoi(r.URL.Query().Get("depth"))
	edges, err := h.svc.ChainDetect(r.Context(), publicKey, depth)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"public_key": publicKey,
		"edges":      edges,
		"depth":      depth,
	})
}

func (h *APIV1Handler) handleUserBans(w http.ResponseWriter, r *http.Request) {
	publicKey := r.PathValue("public_key")
	bans, err := h.svc.ListUserBanHistory(r.Context(), publicKey)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": bans})
}

func (h *APIV1Handler) handleBanUser(w http.ResponseWriter, r *http.Request) {
	u := userFromCtx(r.Context())
	publicKey := r.PathValue("public_key")
	var req struct {
		Reason    string     `json:"reason"`
		ExpiresAt *time.Time `json:"expires_at,omitempty"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	ban, err := h.svc.BanUser(r.Context(), u.ID, publicKey, req.Reason, req.ExpiresAt)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, ban)
}

func (h *APIV1Handler) handleUnbanUser(w http.ResponseWriter, r *http.Request) {
	u := userFromCtx(r.Context())
	publicKey := r.PathValue("public_key")
	var req struct {
		Reason string `json:"reason"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if err := h.svc.UnbanUser(r.Context(), u.ID, publicKey, req.Reason); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (h *APIV1Handler) handleUserRoomBans(w http.ResponseWriter, r *http.Request) {
	publicKey := r.PathValue("public_key")
	bans, err := h.svc.ListUserRoomBans(r.Context(), publicKey)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": bans})
}

func (h *APIV1Handler) handleBanUserFromRoom(w http.ResponseWriter, r *http.Request) {
	u := userFromCtx(r.Context())
	publicKey := r.PathValue("public_key")
	roomUUID := r.PathValue("room_uuid")
	var req struct {
		Reason    string     `json:"reason"`
		ExpiresAt *time.Time `json:"expires_at,omitempty"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	ban, err := h.svc.BanUserFromRoom(r.Context(), u.ID, publicKey, roomUUID, req.Reason, req.ExpiresAt)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, ban)
}

func (h *APIV1Handler) handleUnbanUserFromRoom(w http.ResponseWriter, r *http.Request) {
	u := userFromCtx(r.Context())
	publicKey := r.PathValue("public_key")
	roomUUID := r.PathValue("room_uuid")
	var req struct {
		Reason string `json:"reason"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if err := h.svc.UnbanUserFromRoom(r.Context(), u.ID, publicKey, roomUUID, req.Reason); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (h *APIV1Handler) handlePutUserLimits(w http.ResponseWriter, r *http.Request) {
	u := userFromCtx(r.Context())
	publicKey := r.PathValue("public_key")
	var req struct {
		TrafficLimitBytes  int64  `json:"traffic_limit_bytes"`
		TrafficLimitPeriod string `json:"traffic_limit_period"`
		RequestRateLimit   int    `json:"request_rate_limit"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid request body"})
		return
	}
	if err := h.svc.PutUserTrafficLimits(r.Context(), u.ID, publicKey, req.TrafficLimitBytes, req.TrafficLimitPeriod, req.RequestRateLimit); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (h *APIV1Handler) handleDeleteUserLimits(w http.ResponseWriter, r *http.Request) {
	u := userFromCtx(r.Context())
	publicKey := r.PathValue("public_key")
	if err := h.svc.DeleteUserTrafficLimits(r.Context(), u.ID, publicKey); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ════════════════════════════════════════════════════════════════════
// Bulk User Operations
// ════════════════════════════════════════════════════════════════════

func (h *APIV1Handler) handleBulkBanUsers(w http.ResponseWriter, r *http.Request) {
	u := userFromCtx(r.Context())
	var req struct {
		PublicKeys []string   `json:"public_keys"`
		Reason     string     `json:"reason"`
		ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid request body"})
		return
	}
	count, err := h.svc.BulkBanUsers(r.Context(), u.ID, req.PublicKeys, req.Reason, req.ExpiresAt)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "count": count})
}

func (h *APIV1Handler) handleBulkUnbanUsers(w http.ResponseWriter, r *http.Request) {
	u := userFromCtx(r.Context())
	var req struct {
		PublicKeys []string `json:"public_keys"`
		Reason     string   `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid request body"})
		return
	}
	count, err := h.svc.BulkUnbanUsers(r.Context(), u.ID, req.PublicKeys, req.Reason)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "count": count})
}

func (h *APIV1Handler) handleBulkSetLimits(w http.ResponseWriter, r *http.Request) {
	u := userFromCtx(r.Context())
	var req struct {
		PublicKeys         []string `json:"public_keys"`
		TrafficLimitBytes  int64    `json:"traffic_limit_bytes"`
		TrafficLimitPeriod string   `json:"traffic_limit_period"`
		RequestRateLimit   int      `json:"request_rate_limit"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid request body"})
		return
	}
	count, err := h.svc.BulkSetUserLimits(r.Context(), u.ID, req.PublicKeys, req.TrafficLimitBytes, req.TrafficLimitPeriod, req.RequestRateLimit)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "count": count})
}

// ════════════════════════════════════════════════════════════════════
// Bans (top-level)
// ════════════════════════════════════════════════════════════════════

func (h *APIV1Handler) handleListUserBans(w http.ResponseWriter, r *http.Request) {
	page, perPage := parsePagination(r)
	bans, total, err := h.svc.ListActiveUserBans(r.Context(), perPage, (page-1)*perPage)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writePaginatedJSON(w, bans, total, page, perPage)
}

func (h *APIV1Handler) handleListIPBans(w http.ResponseWriter, r *http.Request) {
	page, perPage := parsePagination(r)
	bans, total, err := h.svc.ListActiveIPBans(r.Context(), perPage, (page-1)*perPage)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writePaginatedJSON(w, bans, total, page, perPage)
}

func (h *APIV1Handler) handleBanIP(w http.ResponseWriter, r *http.Request) {
	u := userFromCtx(r.Context())
	var req struct {
		IPAddress string     `json:"ip_address"`
		Reason    string     `json:"reason"`
		ExpiresAt *time.Time `json:"expires_at,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid request body"})
		return
	}
	ban, err := h.svc.BanIP(r.Context(), u.ID, req.IPAddress, req.Reason, req.ExpiresAt)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, ban)
}

func (h *APIV1Handler) handleIPBanHistory(w http.ResponseWriter, r *http.Request) {
	ipAddress := r.PathValue("ip_address")
	if ipAddress == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "ip_address is required"})
		return
	}
	history, err := h.svc.ListIPBanHistory(r.Context(), ipAddress)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": history})
}

func (h *APIV1Handler) handleUnbanIP(w http.ResponseWriter, r *http.Request) {
	u := userFromCtx(r.Context())
	ipAddress := r.PathValue("ip_address")
	var req struct {
		Reason string `json:"reason"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if err := h.svc.UnbanIP(r.Context(), u.ID, ipAddress, req.Reason); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (h *APIV1Handler) handleListRoomBans(w http.ResponseWriter, r *http.Request) {
	page, perPage := parsePagination(r)
	bans, total, err := h.svc.ListActiveRoomBans(r.Context(), perPage, (page-1)*perPage)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writePaginatedJSON(w, bans, total, page, perPage)
}

// ════════════════════════════════════════════════════════════════════
// Rooms
// ════════════════════════════════════════════════════════════════════

func (h *APIV1Handler) handleListRooms(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	page, perPage := parsePagination(r)
	search := q.Get("search")
	sortBy := q.Get("sort")
	order := q.Get("order")

	items, total, err := h.svc.ListRoomsPaginated(r.Context(), search, sortBy, order, page, perPage)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writePaginatedJSON(w, items, total, page, perPage)
}

func (h *APIV1Handler) handleGetRoom(w http.ResponseWriter, r *http.Request) {
	uuid := r.PathValue("uuid")
	if uuid == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "room uuid is required"})
		return
	}
	info, err := h.svc.GetRoomDetails(r.Context(), uuid)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "room not found"})
		return
	}
	writeJSON(w, http.StatusOK, info)
}

func (h *APIV1Handler) handleRoomParticipants(w http.ResponseWriter, r *http.Request) {
	uuid := r.PathValue("uuid")
	page, perPage := parsePagination(r)
	items, err := h.svc.ListRoomParticipantsV1(r.Context(), uuid, perPage, (page-1)*perPage)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": items})
}

func (h *APIV1Handler) handleRoomParticipantsOnline(w http.ResponseWriter, r *http.Request) {
	uuid := r.PathValue("uuid")
	items, err := h.svc.ListRoomParticipantsOnline(r.Context(), uuid)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": items})
}

func (h *APIV1Handler) handleRoomIPs(w http.ResponseWriter, r *http.Request) {
	uuid := r.PathValue("uuid")
	ips, err := h.svc.ListRoomIPs(r.Context(), uuid)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": ips})
}

func (h *APIV1Handler) handleRoomBansDetail(w http.ResponseWriter, r *http.Request) {
	uuid := r.PathValue("uuid")
	bans, err := h.svc.ListRoomBansV1(r.Context(), uuid)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": bans})
}

func (h *APIV1Handler) handleBanRoom(w http.ResponseWriter, r *http.Request) {
	u := userFromCtx(r.Context())
	uuid := r.PathValue("uuid")
	var req struct {
		Reason    string     `json:"reason"`
		ExpiresAt *time.Time `json:"expires_at,omitempty"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	ban, err := h.svc.BanRoom(r.Context(), u.ID, uuid, req.Reason, req.ExpiresAt)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, ban)
}

func (h *APIV1Handler) handleUnbanRoom(w http.ResponseWriter, r *http.Request) {
	u := userFromCtx(r.Context())
	uuid := r.PathValue("uuid")
	var req struct {
		Reason string `json:"reason"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if err := h.svc.UnbanRoom(r.Context(), u.ID, uuid, req.Reason); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (h *APIV1Handler) handleBanAllUsersInRoom(w http.ResponseWriter, r *http.Request) {
	u := userFromCtx(r.Context())
	uuid := r.PathValue("uuid")
	var req struct {
		Reason    string     `json:"reason"`
		ExpiresAt *time.Time `json:"expires_at,omitempty"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	count, err := h.svc.BanAllUsersInRoom(r.Context(), u.ID, uuid, req.Reason, req.ExpiresAt)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "banned_count": count})
}

// ════════════════════════════════════════════════════════════════════
// Audit Log
// ════════════════════════════════════════════════════════════════════

func (h *APIV1Handler) handleAuditLog(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	page, perPage := parsePagination(r)
	action := q.Get("action")
	objectType := q.Get("object_type")
	objectID := q.Get("object_id")

	items, total, err := h.svc.ListAuditLog(r.Context(), objectType, objectID, action, perPage, (page-1)*perPage)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writePaginatedJSON(w, items, total, page, perPage)
}

func (h *APIV1Handler) handleUserAuditLog(w http.ResponseWriter, r *http.Request) {
	publicKey := r.PathValue("public_key")
	q := r.URL.Query()
	page, perPage := parsePagination(r)
	action := q.Get("action")

	items, total, err := h.svc.ListAuditLog(r.Context(), "", publicKey, action, perPage, (page-1)*perPage)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writePaginatedJSON(w, items, total, page, perPage)
}

func (h *APIV1Handler) handleRoomAuditLog(w http.ResponseWriter, r *http.Request) {
	uuid := r.PathValue("uuid")
	q := r.URL.Query()
	page, perPage := parsePagination(r)
	action := q.Get("action")

	items, total, err := h.svc.ListAuditLog(r.Context(), "", uuid, action, perPage, (page-1)*perPage)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writePaginatedJSON(w, items, total, page, perPage)
}

// ════════════════════════════════════════════════════════════════════
// Settings
// ════════════════════════════════════════════════════════════════════

func (h *APIV1Handler) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	settings, err := h.svc.GetAllPanelSettings(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, settings)
}

func (h *APIV1Handler) handlePatchSettings(w http.ResponseWriter, r *http.Request) {
	u := userFromCtx(r.Context())
	var updates map[string]json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid request body"})
		return
	}
	if err := h.svc.PatchPanelSettings(r.Context(), u.ID, updates); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (h *APIV1Handler) handleListTrustedIPs(w http.ResponseWriter, r *http.Request) {
	ips, err := h.svc.ListTrustedIPs(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": ips})
}

func (h *APIV1Handler) handleAddTrustedIP(w http.ResponseWriter, r *http.Request) {
	u := userFromCtx(r.Context())
	var req struct {
		IPAddress string `json:"ip_address"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid request body"})
		return
	}
	t, err := h.svc.AddTrustedIP(r.Context(), u.ID, req.IPAddress)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, t)
}

func (h *APIV1Handler) handleDeleteTrustedIP(w http.ResponseWriter, r *http.Request) {
	u := userFromCtx(r.Context())
	ip := r.PathValue("ip")
	if ip == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "ip is required"})
		return
	}
	if err := h.svc.DeleteTrustedIP(r.Context(), u.ID, ip); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ════════════════════════════════════════════════════════════════════
// Backups
// ════════════════════════════════════════════════════════════════════

func (h *APIV1Handler) handleListBackups(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 50
	}
	jobs, err := h.svc.ListBackups(r.Context(), limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": jobs})
}

func (h *APIV1Handler) handleTriggerBackup(w http.ResponseWriter, r *http.Request) {
	u := userFromCtx(r.Context())
	jobID, err := h.svc.TriggerBackup(r.Context(), u.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"job_id": jobID, "status": "queued"})
}

func (h *APIV1Handler) handleDeleteBackup(w http.ResponseWriter, r *http.Request) {
	u := userFromCtx(r.Context())
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid backup id"})
		return
	}
	if err := h.svc.DeleteBackupJob(r.Context(), u.ID, id); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (h *APIV1Handler) handleGetBackupSettings(w http.ResponseWriter, r *http.Request) {
	bs, err := h.svc.GetBackupSettings(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, bs)
}

func (h *APIV1Handler) handlePutBackupSettings(w http.ResponseWriter, r *http.Request) {
	u := userFromCtx(r.Context())
	var bs BackupSettings
	if err := json.NewDecoder(r.Body).Decode(&bs); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid request body"})
		return
	}
	if err := h.svc.PutBackupSettings(r.Context(), u.ID, bs); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ════════════════════════════════════════════════════════════════════
// Export
// ════════════════════════════════════════════════════════════════════

func (h *APIV1Handler) handleExport(w http.ResponseWriter, r *http.Request) {
	u := userFromCtx(r.Context())
	jobID, err := h.svc.ExportData(r.Context(), u.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"job_id": jobID, "status": "queued"})
}

// ════════════════════════════════════════════════════════════════════
// Helpers
// ════════════════════════════════════════════════════════════════════

// setUserCtx stores the admin user in the request context.
func setUserCtx(ctx context.Context, u *AdminUser) context.Context {
	return context.WithValue(ctx, userContextKey, u)
}

// parsePagination reads page and per_page query params with sensible defaults.
func parsePagination(r *http.Request) (page, perPage int) {
	page, _ = strconv.Atoi(r.URL.Query().Get("page"))
	perPage, _ = strconv.Atoi(r.URL.Query().Get("per_page"))
	if page <= 0 {
		page = 1
	}
	if perPage <= 0 {
		perPage = 50
	}
	if perPage > 500 {
		perPage = 500
	}
	return page, perPage
}

// writePaginatedJSON writes the standard paginated response envelope.
func writePaginatedJSON(w http.ResponseWriter, data any, total int64, page, perPage int) {
	totalPages := int64(math.Ceil(float64(total) / float64(perPage)))
	if totalPages < 1 {
		totalPages = 1
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"data": data,
		"meta": map[string]any{
			"total":       total,
			"page":        page,
			"per_page":    perPage,
			"total_pages": totalPages,
		},
	})
}

