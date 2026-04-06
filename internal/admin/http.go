package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type contextKey string

const userContextKey contextKey = "admin.user"

type HTTPHandler struct {
	svc *Service
}

func NewHTTPHandler(svc *Service) *HTTPHandler {
	return &HTTPHandler{svc: svc}
}

func (h *HTTPHandler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /admin", h.handleUI)
	mux.HandleFunc("GET /admin/", h.handleUI)
	mux.HandleFunc("POST /admin/auth/login", h.handleLogin)
	mux.HandleFunc("POST /admin/auth/refresh", h.handleRefresh)
	mux.HandleFunc("POST /admin/auth/logout", h.requireAuth(h.handleLogout))

	mux.HandleFunc("GET /admin/settings/network", h.requireAuth(h.handleGetNetworkSettings))
	mux.HandleFunc("PUT /admin/settings/network", h.requireAuth(h.handlePutNetworkSettings))
	mux.HandleFunc("GET /admin/settings/access", h.requireAuth(h.handleGetAccessSettings))
	mux.HandleFunc("PUT /admin/settings/access", h.requireAuth(h.handlePutAccessSettings))
	mux.HandleFunc("GET /admin/limits", h.requireAuth(h.handleGetLimits))
	mux.HandleFunc("PUT /admin/limits", h.requireAuth(h.handlePutLimits))

	mux.HandleFunc("GET /admin/bans", h.requireAuth(h.handleListBans))
	mux.HandleFunc("POST /admin/bans", h.requireAuth(h.handleCreateBan))
	mux.HandleFunc("DELETE /admin/bans", h.requireAuth(h.handleDeleteBan))

	mux.HandleFunc("GET /admin/stats/usage", h.requireAuth(h.handleStatsUsage))
	mux.HandleFunc("GET /admin/stats/users", h.requireAuth(h.handleStatsUsers))

	mux.HandleFunc("POST /admin/backups/run", h.requireAuth(h.handleBackupRun))
	mux.HandleFunc("GET /admin/backups", h.requireAuth(h.handleBackupList))

	mux.HandleFunc("POST /admin/users", h.requireAuth(h.handleCreateUser))
	mux.HandleFunc("POST /admin/users/change-password", h.requireAuth(h.handleChangePassword))
}

func (h *HTTPHandler) handleUI(w http.ResponseWriter, _ *http.Request) {
	page, err := loadUIPage()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "admin ui not found"})
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(page)
}

func (h *HTTPHandler) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hdr := r.Header.Get("Authorization")
		parts := strings.SplitN(hdr, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "missing bearer token"})
			return
		}
		uid, _, err := h.svc.ParseAccessToken(parts[1])
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid token"})
			return
		}
		u, err := h.svc.GetUser(r.Context(), uid)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "user not found"})
			return
		}
		ctx := context.WithValue(r.Context(), userContextKey, u)
		next(w, r.WithContext(ctx))
	}
}

func userFromCtx(ctx context.Context) *AdminUser {
	v := ctx.Value(userContextKey)
	u, _ := v.(*AdminUser)
	return u
}

func (h *HTTPHandler) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		LoginName string `json:"login_name"`
		Password  string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	res, err := h.svc.Login(r.Context(), req.LoginName, req.Password, r.UserAgent(), ip)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (h *HTTPHandler) handleRefresh(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	res, err := h.svc.Refresh(r.Context(), req.RefreshToken)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (h *HTTPHandler) handleLogout(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	u := userFromCtx(r.Context())
	if u == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	if err := h.svc.Logout(r.Context(), req.RefreshToken, u.ID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (h *HTTPHandler) handleGetNetworkSettings(w http.ResponseWriter, r *http.Request) {
	raw, err := h.svc.GetNetworkSettings(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeRawJSON(w, http.StatusOK, raw)
}

func (h *HTTPHandler) handlePutNetworkSettings(w http.ResponseWriter, r *http.Request) {
	u := userFromCtx(r.Context())
	if u == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	raw, err := readBodyRawJSON(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	if err := h.svc.PutNetworkSettings(r.Context(), u.ID, raw); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"apply":    "saved; apply with graceful restart/reload",
		"saved_at": time.Now().UTC(),
	})
}

func (h *HTTPHandler) handleGetAccessSettings(w http.ResponseWriter, r *http.Request) {
	p, err := h.svc.GetAccessPolicy(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (h *HTTPHandler) handlePutAccessSettings(w http.ResponseWriter, r *http.Request) {
	u := userFromCtx(r.Context())
	if u == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	var p AccessPolicy
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	if err := h.svc.PutAccessPolicy(r.Context(), u.ID, p); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (h *HTTPHandler) handleGetLimits(w http.ResponseWriter, r *http.Request) {
	l, err := h.svc.GetUsageLimits(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, l)
}

func (h *HTTPHandler) handlePutLimits(w http.ResponseWriter, r *http.Request) {
	u := userFromCtx(r.Context())
	if u == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	var l UsageLimits
	if err := json.NewDecoder(r.Body).Decode(&l); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	if err := h.svc.PutUsageLimits(r.Context(), u.ID, l); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (h *HTTPHandler) handleListBans(w http.ResponseWriter, r *http.Request) {
	bans, err := h.svc.ListBans(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, bans)
}

func (h *HTTPHandler) handleCreateBan(w http.ResponseWriter, r *http.Request) {
	u := userFromCtx(r.Context())
	if u == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	var b BanRule
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	out, err := h.svc.AddBan(r.Context(), u.ID, b)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *HTTPHandler) handleDeleteBan(w http.ResponseWriter, r *http.Request) {
	u := userFromCtx(r.Context())
	if u == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	idStr := r.URL.Query().Get("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid id"})
		return
	}
	if err := h.svc.DeleteBan(r.Context(), u.ID, id); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (h *HTTPHandler) handleStatsUsage(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	items, err := h.svc.UsageStats(r.Context(), limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, items)
}

func (h *HTTPHandler) handleStatsUsers(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	items, err := h.svc.UsersStats(r.Context(), limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, items)
}

func (h *HTTPHandler) handleBackupRun(w http.ResponseWriter, r *http.Request) {
	u := userFromCtx(r.Context())
	if u == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	id, err := h.svc.TriggerBackup(r.Context(), u.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"job_id": id, "status": "queued"})
}

func (h *HTTPHandler) handleBackupList(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	jobs, err := h.svc.ListBackups(r.Context(), limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, jobs)
}

func (h *HTTPHandler) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	actor := userFromCtx(r.Context())
	if actor == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	var req struct {
		LoginName           string `json:"login_name"`
		DisplayName         string `json:"display_name"`
		Password            string `json:"password"`
		ForcePasswordChange bool   `json:"force_password_change"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	if strings.TrimSpace(req.LoginName) == "" || strings.TrimSpace(req.Password) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "login_name and password are required"})
		return
	}
	if req.DisplayName == "" {
		req.DisplayName = req.LoginName
	}
	u, err := h.svc.CreateAdmin(r.Context(), actor, req.LoginName, req.DisplayName, req.Password, req.ForcePasswordChange)
	if err != nil {
		code := http.StatusInternalServerError
		if strings.Contains(strings.ToLower(err.Error()), "forbidden") {
			code = http.StatusForbidden
		}
		writeJSON(w, code, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, u)
}

func (h *HTTPHandler) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	actor := userFromCtx(r.Context())
	if actor == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	var req struct {
		NewPassword string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	if strings.TrimSpace(req.NewPassword) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "new_password is required"})
		return
	}
	if err := h.svc.ChangePassword(r.Context(), actor.ID, req.NewPassword, true); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeRawJSON(w http.ResponseWriter, code int, raw []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write(raw)
}

func readBodyRawJSON(r *http.Request) ([]byte, error) {
	var raw json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("empty json body")
	}
	return raw, nil
}
