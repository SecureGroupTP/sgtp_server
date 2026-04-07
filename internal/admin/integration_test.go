package admin_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/SecureGroupTP/sgtp_server/internal/admin"
)

// ════════════════════════════════════════════════════════════════════
// Test infrastructure: Postgres container + template DB + per-test DB
// ════════════════════════════════════════════════════════════════════

var templateDSN string

func TestMain(m *testing.M) {
	ctx := context.Background()

	container, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithDatabase("template_sgtp"),
		postgres.WithUsername("test"),
		postgres.WithPassword("test"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(60*time.Second),
		),
	)
	if err != nil {
		log.Fatalf("start postgres container: %v", err)
	}

	dsn, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		log.Fatalf("get connection string: %v", err)
	}
	templateDSN = dsn

	db, err := sql.Open("pgx", templateDSN)
	if err != nil {
		log.Fatalf("open template db: %v", err)
	}
	if err := runMigrations(db); err != nil {
		log.Fatalf("run migrations: %v", err)
	}
	db.Close()

	code := m.Run()
	_ = container.Terminate(ctx)
	os.Exit(code)
}

func runMigrations(db *sql.DB) error {
	migrationsDir := findMigrationsDir()
	files := []string{
		"V1__userdir_baseline.sql",
		"V2__admin_control_plane.sql",
		"V3__client_activity_dedup_and_pubkey_normalize.sql",
		"V4__usage_subject_limits.sql",
		"V5__room_activity_and_extended_constraints.sql",
		"V6__room_user_activity.sql",
		"V7__admin_panel_v2.sql",
		"V8__userdir_profiles_table.sql",
	}
	for _, f := range files {
		content, err := os.ReadFile(filepath.Join(migrationsDir, f))
		if err != nil {
			return fmt.Errorf("read %s: %w", f, err)
		}
		if _, err := db.Exec(string(content)); err != nil {
			return fmt.Errorf("exec %s: %w", f, err)
		}
	}
	return nil
}

func findMigrationsDir() string {
	dir, _ := os.Getwd()
	for i := 0; i < 10; i++ {
		candidate := filepath.Join(dir, "db", "migrations")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		dir = filepath.Dir(dir)
	}
	return "/data/vibe-kanban/worktrees/263f-add-integration/sgtp_server/db/migrations"
}

// testEnv holds per-test server + client state.
type testEnv struct {
	t         *testing.T
	server    *httptest.Server
	dbName    string
	rootLogin string
	rootPass  string
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	ctx := context.Background()

	adminDB, err := sql.Open("pgx", templateDSN)
	require.NoError(t, err)
	defer adminDB.Close()

	// Create unique DB name from test name
	dbName := sanitizeDBName(fmt.Sprintf("t_%d", time.Now().UnixNano()))

	_, err = adminDB.ExecContext(ctx, fmt.Sprintf(
		`CREATE DATABASE %s TEMPLATE template_sgtp`, dbName))
	require.NoError(t, err)

	// Build DSN for new test DB
	testDSN := replaceDSNDatabase(templateDSN, "template_sgtp", dbName)

	st, err := admin.OpenStore(ctx, testDSN)
	require.NoError(t, err)

	bootstrapFile := filepath.Join(t.TempDir(), "bootstrap_creds.txt")
	svc, err := admin.NewService(admin.Config{
		Store:            st,
		JWTSecret:        []byte("test-jwt-secret-for-integration-tests"),
		AccessTTL:        15 * time.Minute,
		RefreshTTL:       7 * 24 * time.Hour,
		BootstrapOutFile: bootstrapFile,
		PGDSN:            testDSN,
	})
	require.NoError(t, err)

	err = svc.EnsureBootstrapRoot(ctx)
	require.NoError(t, err)

	// Read bootstrap credentials
	rootLogin, rootPass := readBootstrapCreds(t, bootstrapFile)

	mux := http.NewServeMux()
	handler := admin.NewAPIV1Handler(svc)
	handler.Register(mux)
	ts := httptest.NewServer(mux)

	env := &testEnv{
		t:         t,
		server:    ts,
		dbName:    dbName,
		rootLogin: rootLogin,
		rootPass:  rootPass,
	}

	t.Cleanup(func() {
		ts.Close()
		st.Close()
		cleanDB, cerr := sql.Open("pgx", templateDSN)
		if cerr == nil {
			_, _ = cleanDB.Exec(fmt.Sprintf(`DROP DATABASE IF EXISTS %s WITH (FORCE)`, dbName))
			cleanDB.Close()
		}
	})

	return env
}

func readBootstrapCreds(t *testing.T, path string) (login, pass string) {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err, "read bootstrap credentials file")
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "BOOTSTRAP_ROOT_LOGIN=") {
			login = strings.TrimPrefix(line, "BOOTSTRAP_ROOT_LOGIN=")
		}
		if strings.HasPrefix(line, "BOOTSTRAP_ROOT_PASSWORD=") {
			pass = strings.TrimPrefix(line, "BOOTSTRAP_ROOT_PASSWORD=")
		}
	}
	require.NotEmpty(t, login)
	require.NotEmpty(t, pass)
	return
}

func sanitizeDBName(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' {
			b.WriteRune(c)
		} else {
			b.WriteRune('_')
		}
	}
	result := b.String()
	if len(result) > 63 {
		result = result[:63]
	}
	return result
}

func replaceDSNDatabase(dsn, oldDB, newDB string) string {
	// Handle both formats: dbname= and /dbname?
	result := strings.Replace(dsn, "dbname="+oldDB, "dbname="+newDB, 1)
	result = strings.Replace(result, "/"+oldDB+"?", "/"+newDB+"?", 1)
	result = strings.Replace(result, "/"+oldDB+" ", "/"+newDB+" ", 1)
	if strings.HasSuffix(result, "/"+oldDB) {
		result = result[:len(result)-len(oldDB)] + newDB
	}
	return result
}

// rootToken logs in as root and returns the access token.
func (e *testEnv) rootToken() string {
	e.t.Helper()
	return e.loginAs(e.rootLogin, e.rootPass)
}

func (e *testEnv) loginAs(login, password string) string {
	e.t.Helper()
	resp := e.post("/api/v1/auth/login", map[string]string{
		"login_name": login,
		"password":   password,
	}, "")
	require.Equal(e.t, http.StatusOK, resp.StatusCode, "login failed: %s", peekBody(resp))
	var result map[string]any
	mustDecodeJSON(e.t, resp, &result)
	token, ok := result["access_token"].(string)
	require.True(e.t, ok, "no access_token in response")
	return token
}

func (e *testEnv) refreshToken() string {
	e.t.Helper()
	resp := e.post("/api/v1/auth/login", map[string]string{
		"login_name": e.rootLogin,
		"password":   e.rootPass,
	}, "")
	require.Equal(e.t, http.StatusOK, resp.StatusCode)
	var result map[string]any
	mustDecodeJSON(e.t, resp, &result)
	rt, _ := result["refresh_token"].(string)
	return rt
}

// ── HTTP helpers ──────────────────────────────────────────────────

func (e *testEnv) get(path, token string) *http.Response {
	e.t.Helper()
	return e.do("GET", path, nil, token)
}

func (e *testEnv) post(path string, body any, token string) *http.Response {
	e.t.Helper()
	return e.do("POST", path, body, token)
}

func (e *testEnv) put(path string, body any, token string) *http.Response {
	e.t.Helper()
	return e.do("PUT", path, body, token)
}

func (e *testEnv) patch(path string, body any, token string) *http.Response {
	e.t.Helper()
	return e.do("PATCH", path, body, token)
}

func (e *testEnv) del(path, token string) *http.Response {
	e.t.Helper()
	return e.do("DELETE", path, nil, token)
}

func (e *testEnv) do(method, path string, body any, token string) *http.Response {
	e.t.Helper()
	var r io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		require.NoError(e.t, err)
		r = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, e.server.URL+path, r)
	require.NoError(e.t, err)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(e.t, err)
	return resp
}

func mustDecodeJSON(t *testing.T, resp *http.Response, v any) {
	t.Helper()
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(data, v), "body: %s", string(data))
}

func peekBody(resp *http.Response) string {
	data, _ := io.ReadAll(resp.Body)
	resp.Body = io.NopCloser(bytes.NewReader(data))
	return string(data)
}

func respJSON(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	var m map[string]any
	mustDecodeJSON(t, resp, &m)
	return m
}

// ════════════════════════════════════════════════════════════════════
// Auth endpoint tests
// ════════════════════════════════════════════════════════════════════

func TestAuthLogin(t *testing.T) {
	env := newTestEnv(t)

	t.Run("valid login", func(t *testing.T) {
		resp := env.post("/api/v1/auth/login", map[string]string{
			"login_name": env.rootLogin,
			"password":   env.rootPass,
		}, "")
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		m := respJSON(t, resp)
		assert.NotEmpty(t, m["access_token"])
		assert.NotEmpty(t, m["refresh_token"])
		assert.NotNil(t, m["user"])
	})

	t.Run("invalid password", func(t *testing.T) {
		resp := env.post("/api/v1/auth/login", map[string]string{
			"login_name": env.rootLogin,
			"password":   "wrong",
		}, "")
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("unknown user", func(t *testing.T) {
		resp := env.post("/api/v1/auth/login", map[string]string{
			"login_name": "nonexistent",
			"password":   "pass",
		}, "")
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("invalid body", func(t *testing.T) {
		req, _ := http.NewRequest("POST", env.server.URL+"/api/v1/auth/login",
			strings.NewReader("not json"))
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		resp.Body.Close()
	})
}

func TestAuthLogout(t *testing.T) {
	env := newTestEnv(t)
	token := env.rootToken()
	rt := env.refreshToken()

	resp := env.post("/api/v1/auth/logout", map[string]string{
		"refresh_token": rt,
	}, token)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	m := respJSON(t, resp)
	assert.Equal(t, true, m["ok"])
}

func TestAuthMe(t *testing.T) {
	env := newTestEnv(t)

	t.Run("authenticated", func(t *testing.T) {
		token := env.rootToken()
		resp := env.get("/api/v1/auth/me", token)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		m := respJSON(t, resp)
		assert.Equal(t, env.rootLogin, m["login_name"])
		assert.Equal(t, "root", m["role"])
	})

	t.Run("unauthenticated", func(t *testing.T) {
		resp := env.get("/api/v1/auth/me", "")
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("bad token", func(t *testing.T) {
		resp := env.get("/api/v1/auth/me", "invalid-token")
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})
}

// ════════════════════════════════════════════════════════════════════
// Invite endpoint tests
// ════════════════════════════════════════════════════════════════════

func TestInvites(t *testing.T) {
	env := newTestEnv(t)
	token := env.rootToken()

	// List invites (initially empty)
	t.Run("list empty", func(t *testing.T) {
		resp := env.get("/api/v1/invites", token)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		m := respJSON(t, resp)
		assert.NotNil(t, m["data"])
		meta, _ := m["meta"].(map[string]any)
		assert.NotNil(t, meta)
	})

	// Create invite
	var inviteID float64
	var inviteToken string
	t.Run("create invite", func(t *testing.T) {
		resp := env.post("/api/v1/invites", map[string]any{
			"ttl_hours": 24,
		}, token)
		assert.Equal(t, http.StatusCreated, resp.StatusCode)
		m := respJSON(t, resp)
		inviteID, _ = m["id"].(float64)
		inviteToken, _ = m["token"].(string)
		assert.NotZero(t, inviteID)
		assert.NotEmpty(t, inviteToken)
		assert.Equal(t, "pending", m["status"])
	})

	// List invites (now has one)
	t.Run("list with one", func(t *testing.T) {
		resp := env.get("/api/v1/invites", token)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		m := respJSON(t, resp)
		data, _ := m["data"].([]any)
		assert.Len(t, data, 1)
	})

	// Register with invite
	t.Run("register with invite", func(t *testing.T) {
		resp := env.post(fmt.Sprintf("/api/v1/invites/%s/register", inviteToken), map[string]string{
			"login_name": "newadmin",
			"password":   "newpassword123",
		}, "")
		assert.Equal(t, http.StatusCreated, resp.StatusCode)
		m := respJSON(t, resp)
		assert.Equal(t, "newadmin", m["login_name"])
		assert.Equal(t, "admin", m["role"])
	})

	// Create another invite and revoke it
	t.Run("revoke invite", func(t *testing.T) {
		resp := env.post("/api/v1/invites", map[string]any{
			"ttl_hours": 24,
		}, token)
		assert.Equal(t, http.StatusCreated, resp.StatusCode)
		m := respJSON(t, resp)
		revokeID := m["id"].(float64)

		resp = env.post(fmt.Sprintf("/api/v1/invites/%d/revoke", int64(revokeID)), nil, token)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	// Register with invalid token
	t.Run("register invalid token", func(t *testing.T) {
		resp := env.post("/api/v1/invites/invalidtoken/register", map[string]string{
			"login_name": "fail",
			"password":   "pass",
		}, "")
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})
}

// ════════════════════════════════════════════════════════════════════
// Admin management tests
// ════════════════════════════════════════════════════════════════════

func TestAdmins(t *testing.T) {
	env := newTestEnv(t)
	token := env.rootToken()

	t.Run("list admins", func(t *testing.T) {
		resp := env.get("/api/v1/admins", token)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		m := respJSON(t, resp)
		data, _ := m["data"].([]any)
		assert.GreaterOrEqual(t, len(data), 1) // at least root
	})

	t.Run("deactivate nonexistent", func(t *testing.T) {
		resp := env.post("/api/v1/admins/nonexistent/deactivate", nil, token)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	// Create an admin via invite, then deactivate
	t.Run("deactivate admin", func(t *testing.T) {
		// Create invite
		resp := env.post("/api/v1/invites", map[string]any{"ttl_hours": 24}, token)
		require.Equal(t, http.StatusCreated, resp.StatusCode)
		m := respJSON(t, resp)
		invToken := m["token"].(string)

		// Register
		resp = env.post(fmt.Sprintf("/api/v1/invites/%s/register", invToken), map[string]string{
			"login_name": "todeactivate",
			"password":   "pass123",
		}, "")
		require.Equal(t, http.StatusCreated, resp.StatusCode)

		// Deactivate
		resp = env.post("/api/v1/admins/todeactivate/deactivate", nil, token)
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		// Verify deactivated admin cannot log in
		resp = env.post("/api/v1/auth/login", map[string]string{
			"login_name": "todeactivate",
			"password":   "pass123",
		}, "")
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("unauthenticated", func(t *testing.T) {
		resp := env.get("/api/v1/admins", "")
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})
}

// ════════════════════════════════════════════════════════════════════
// Sessions tests
// ════════════════════════════════════════════════════════════════════

func TestSessions(t *testing.T) {
	env := newTestEnv(t)
	token := env.rootToken()

	resp := env.get("/api/v1/sessions", token)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	m := respJSON(t, resp)
	data, _ := m["data"].([]any)
	assert.GreaterOrEqual(t, len(data), 1) // at least the current session
}

// ════════════════════════════════════════════════════════════════════
// Dashboard tests
// ════════════════════════════════════════════════════════════════════

func TestDashboardMetrics(t *testing.T) {
	env := newTestEnv(t)
	token := env.rootToken()

	resp := env.get("/api/v1/dashboard/metrics", token)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	m := respJSON(t, resp)
	// Should have metric fields
	assert.Contains(t, m, "total_users")
	assert.Contains(t, m, "total_rooms")
	assert.Contains(t, m, "active_admins")
}

func TestDashboardCharts(t *testing.T) {
	env := newTestEnv(t)
	token := env.rootToken()

	for _, chartType := range []string{"requests", "traffic", "users", "rooms"} {
		t.Run(chartType, func(t *testing.T) {
			resp := env.get(fmt.Sprintf("/api/v1/dashboard/charts/%s?days=7", chartType), token)
			assert.Equal(t, http.StatusOK, resp.StatusCode)
			m := respJSON(t, resp)
			assert.Equal(t, chartType, m["chart_type"])
		})
	}

	t.Run("unknown chart type", func(t *testing.T) {
		resp := env.get("/api/v1/dashboard/charts/unknown", token)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})
}

// ════════════════════════════════════════════════════════════════════
// Users tests
// ════════════════════════════════════════════════════════════════════

func TestUsers(t *testing.T) {
	env := newTestEnv(t)
	token := env.rootToken()

	t.Run("list users empty", func(t *testing.T) {
		resp := env.get("/api/v1/users", token)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		m := respJSON(t, resp)
		assert.NotNil(t, m["data"])
		assert.NotNil(t, m["meta"])
	})

	t.Run("get nonexistent user", func(t *testing.T) {
		resp := env.get("/api/v1/users/nonexistent_pubkey", token)
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})

	t.Run("user sub-resources on nonexistent", func(t *testing.T) {
		// IPs
		resp := env.get("/api/v1/users/nonexistent/ips", token)
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		// Rooms
		resp = env.get("/api/v1/users/nonexistent/rooms", token)
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		// Chain
		resp = env.get("/api/v1/users/nonexistent/chain", token)
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		// Bans
		resp = env.get("/api/v1/users/nonexistent/bans", token)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})
}

// ════════════════════════════════════════════════════════════════════
// User ban tests
// ════════════════════════════════════════════════════════════════════

func TestUserBans(t *testing.T) {
	env := newTestEnv(t)
	token := env.rootToken()
	pubKey := "test_pubkey_abc123"

	t.Run("ban user", func(t *testing.T) {
		resp := env.post(fmt.Sprintf("/api/v1/users/%s/ban", pubKey), map[string]string{
			"reason": "test ban",
		}, token)
		assert.Equal(t, http.StatusCreated, resp.StatusCode)
		m := respJSON(t, resp)
		assert.Equal(t, pubKey, m["public_key"])
		assert.Equal(t, "test ban", m["reason"])
	})

	t.Run("list user bans", func(t *testing.T) {
		resp := env.get(fmt.Sprintf("/api/v1/users/%s/bans", pubKey), token)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		m := respJSON(t, resp)
		data, _ := m["data"].([]any)
		assert.GreaterOrEqual(t, len(data), 1)
	})

	t.Run("unban user", func(t *testing.T) {
		resp := env.post(fmt.Sprintf("/api/v1/users/%s/unban", pubKey), map[string]string{
			"reason": "test unban",
		}, token)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("user room bans", func(t *testing.T) {
		resp := env.get(fmt.Sprintf("/api/v1/users/%s/room-bans", pubKey), token)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})
}

func TestUserRoomBan(t *testing.T) {
	env := newTestEnv(t)
	token := env.rootToken()
	pubKey := "test_pubkey_room"
	roomUUID := "test-room-uuid-123"

	t.Run("ban user from room", func(t *testing.T) {
		resp := env.post(fmt.Sprintf("/api/v1/users/%s/rooms/%s/ban", pubKey, roomUUID),
			map[string]string{"reason": "room ban"}, token)
		assert.Equal(t, http.StatusCreated, resp.StatusCode)
		m := respJSON(t, resp)
		assert.Equal(t, pubKey, m["public_key"])
		assert.Equal(t, roomUUID, m["room_uuid"])
	})

	t.Run("unban user from room", func(t *testing.T) {
		resp := env.post(fmt.Sprintf("/api/v1/users/%s/rooms/%s/unban", pubKey, roomUUID),
			map[string]string{"reason": "room unban"}, token)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})
}

func TestUserLimits(t *testing.T) {
	env := newTestEnv(t)
	token := env.rootToken()
	pubKey := "test_pubkey_limits"

	t.Run("put user limits", func(t *testing.T) {
		resp := env.put(fmt.Sprintf("/api/v1/users/%s/limits", pubKey), map[string]any{
			"traffic_limit_bytes":  1000000,
			"traffic_limit_period": "per_day",
			"request_rate_limit":   100,
		}, token)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("delete user limits", func(t *testing.T) {
		resp := env.del(fmt.Sprintf("/api/v1/users/%s/limits", pubKey), token)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})
}

func TestUserAuditLog(t *testing.T) {
	env := newTestEnv(t)
	token := env.rootToken()

	// Create some audit activity first (login creates audit entries)
	resp := env.get("/api/v1/users/somepubkey/audit-log", token)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	m := respJSON(t, resp)
	assert.NotNil(t, m["data"])
}

// ════════════════════════════════════════════════════════════════════
// Bulk user operations
// ════════════════════════════════════════════════════════════════════

func TestBulkBanUsers(t *testing.T) {
	env := newTestEnv(t)
	token := env.rootToken()

	t.Run("bulk ban", func(t *testing.T) {
		resp := env.post("/api/v1/users/bulk/ban", map[string]any{
			"public_keys": []string{"pk1", "pk2", "pk3"},
			"reason":      "bulk ban test",
		}, token)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		m := respJSON(t, resp)
		assert.Equal(t, true, m["ok"])
		count, _ := m["count"].(float64)
		assert.Equal(t, float64(3), count)
	})

	t.Run("bulk unban", func(t *testing.T) {
		resp := env.post("/api/v1/users/bulk/unban", map[string]any{
			"public_keys": []string{"pk1", "pk2"},
			"reason":      "bulk unban test",
		}, token)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		m := respJSON(t, resp)
		assert.Equal(t, true, m["ok"])
	})

	t.Run("bulk set limits", func(t *testing.T) {
		resp := env.put("/api/v1/users/bulk/limits", map[string]any{
			"public_keys":          []string{"pk1", "pk2"},
			"traffic_limit_bytes":  5000000,
			"traffic_limit_period": "per_day",
			"request_rate_limit":   50,
		}, token)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		m := respJSON(t, resp)
		assert.Equal(t, true, m["ok"])
	})

	t.Run("bulk ban empty", func(t *testing.T) {
		resp := env.post("/api/v1/users/bulk/ban", map[string]any{
			"public_keys": []string{},
			"reason":      "empty",
		}, token)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})
}

// ════════════════════════════════════════════════════════════════════
// Top-level Bans tests
// ════════════════════════════════════════════════════════════════════

func TestBansUsers(t *testing.T) {
	env := newTestEnv(t)
	token := env.rootToken()

	t.Run("list user bans empty", func(t *testing.T) {
		resp := env.get("/api/v1/bans/users", token)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		m := respJSON(t, resp)
		assert.NotNil(t, m["data"])
	})

	// Ban a user, then verify it appears in the list
	t.Run("ban then list", func(t *testing.T) {
		env.post("/api/v1/users/bantest_pk/ban", map[string]string{"reason": "test"}, token)
		resp := env.get("/api/v1/bans/users", token)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		m := respJSON(t, resp)
		data, _ := m["data"].([]any)
		assert.GreaterOrEqual(t, len(data), 1)
	})
}

func TestBansIPs(t *testing.T) {
	env := newTestEnv(t)
	token := env.rootToken()

	t.Run("list ip bans empty", func(t *testing.T) {
		resp := env.get("/api/v1/bans/ips", token)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("ban ip", func(t *testing.T) {
		resp := env.post("/api/v1/bans/ips", map[string]string{
			"ip_address": "192.168.1.100",
			"reason":     "test ip ban",
		}, token)
		assert.Equal(t, http.StatusCreated, resp.StatusCode)
		m := respJSON(t, resp)
		assert.Equal(t, "192.168.1.100", m["ip_address"])
	})

	t.Run("list ip bans with one", func(t *testing.T) {
		resp := env.get("/api/v1/bans/ips", token)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		m := respJSON(t, resp)
		data, _ := m["data"].([]any)
		assert.GreaterOrEqual(t, len(data), 1)
	})

	t.Run("ip ban history", func(t *testing.T) {
		resp := env.get("/api/v1/bans/ips/192.168.1.100/history", token)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		m := respJSON(t, resp)
		data, _ := m["data"].([]any)
		assert.GreaterOrEqual(t, len(data), 1)
	})

	t.Run("unban ip", func(t *testing.T) {
		resp := env.post("/api/v1/bans/ips/192.168.1.100/unban", map[string]string{
			"reason": "test unban",
		}, token)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("ban ip missing address", func(t *testing.T) {
		resp := env.post("/api/v1/bans/ips", map[string]string{
			"ip_address": "",
			"reason":     "no ip",
		}, token)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})
}

func TestBansRooms(t *testing.T) {
	env := newTestEnv(t)
	token := env.rootToken()

	resp := env.get("/api/v1/bans/rooms", token)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	m := respJSON(t, resp)
	assert.NotNil(t, m["data"])
}

// ════════════════════════════════════════════════════════════════════
// Rooms tests
// ════════════════════════════════════════════════════════════════════

func TestRooms(t *testing.T) {
	env := newTestEnv(t)
	token := env.rootToken()

	t.Run("list rooms empty", func(t *testing.T) {
		resp := env.get("/api/v1/rooms", token)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		m := respJSON(t, resp)
		assert.NotNil(t, m["data"])
	})

	t.Run("get nonexistent room", func(t *testing.T) {
		resp := env.get("/api/v1/rooms/nonexistent-uuid", token)
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})

	t.Run("room participants nonexistent", func(t *testing.T) {
		resp := env.get("/api/v1/rooms/nonexistent-uuid/participants", token)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("room participants online nonexistent", func(t *testing.T) {
		resp := env.get("/api/v1/rooms/nonexistent-uuid/participants/online", token)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("room ips nonexistent", func(t *testing.T) {
		resp := env.get("/api/v1/rooms/nonexistent-uuid/ips", token)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("room bans nonexistent", func(t *testing.T) {
		resp := env.get("/api/v1/rooms/nonexistent-uuid/bans", token)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})
}

func TestRoomBan(t *testing.T) {
	env := newTestEnv(t)
	token := env.rootToken()
	roomUUID := "test-room-ban-uuid"

	t.Run("ban room", func(t *testing.T) {
		resp := env.post(fmt.Sprintf("/api/v1/rooms/%s/ban", roomUUID),
			map[string]string{"reason": "room ban"}, token)
		assert.Equal(t, http.StatusCreated, resp.StatusCode)
		m := respJSON(t, resp)
		assert.Equal(t, roomUUID, m["room_uuid"])
	})

	t.Run("unban room", func(t *testing.T) {
		resp := env.post(fmt.Sprintf("/api/v1/rooms/%s/unban", roomUUID),
			map[string]string{"reason": "room unban"}, token)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("ban all users in room", func(t *testing.T) {
		resp := env.post(fmt.Sprintf("/api/v1/rooms/%s/ban-all-users", roomUUID),
			map[string]string{"reason": "nuke room"}, token)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		m := respJSON(t, resp)
		assert.Equal(t, true, m["ok"])
	})
}

func TestRoomAuditLog(t *testing.T) {
	env := newTestEnv(t)
	token := env.rootToken()

	resp := env.get("/api/v1/rooms/some-room/audit-log", token)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	m := respJSON(t, resp)
	assert.NotNil(t, m["data"])
}

// ════════════════════════════════════════════════════════════════════
// Audit Log tests
// ════════════════════════════════════════════════════════════════════

func TestAuditLog(t *testing.T) {
	env := newTestEnv(t)
	token := env.rootToken()

	// Login generates audit entries
	t.Run("list audit log", func(t *testing.T) {
		resp := env.get("/api/v1/audit-log", token)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		m := respJSON(t, resp)
		assert.NotNil(t, m["data"])
		data, _ := m["data"].([]any)
		assert.GreaterOrEqual(t, len(data), 1) // at least the login audit entry
	})

	t.Run("filter by action", func(t *testing.T) {
		resp := env.get("/api/v1/audit-log?action=auth", token)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("pagination", func(t *testing.T) {
		resp := env.get("/api/v1/audit-log?page=1&per_page=5", token)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		m := respJSON(t, resp)
		meta, _ := m["meta"].(map[string]any)
		assert.NotNil(t, meta)
	})
}

// ════════════════════════════════════════════════════════════════════
// Settings tests
// ════════════════════════════════════════════════════════════════════

func TestSettings(t *testing.T) {
	env := newTestEnv(t)
	token := env.rootToken()

	t.Run("get settings", func(t *testing.T) {
		resp := env.get("/api/v1/settings", token)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		m := respJSON(t, resp)
		// Should have default panel settings
		assert.NotEmpty(t, m)
	})

	t.Run("patch settings", func(t *testing.T) {
		resp := env.patch("/api/v1/settings", map[string]any{
			"online_timeout_seconds": 120,
		}, token)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		m := respJSON(t, resp)
		assert.Equal(t, true, m["ok"])
	})

	t.Run("verify patched setting", func(t *testing.T) {
		resp := env.get("/api/v1/settings", token)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		m := respJSON(t, resp)
		assert.NotNil(t, m["online_timeout_seconds"])
	})

	t.Run("unauthenticated", func(t *testing.T) {
		resp := env.get("/api/v1/settings", "")
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})
}

// ════════════════════════════════════════════════════════════════════
// Trusted IPs tests
// ════════════════════════════════════════════════════════════════════

func TestTrustedIPs(t *testing.T) {
	env := newTestEnv(t)
	token := env.rootToken()

	t.Run("list empty", func(t *testing.T) {
		resp := env.get("/api/v1/settings/trusted-ips", token)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		m := respJSON(t, resp)
		data, _ := m["data"].([]any)
		assert.Empty(t, data)
	})

	t.Run("add trusted ip", func(t *testing.T) {
		resp := env.post("/api/v1/settings/trusted-ips", map[string]string{
			"ip_address": "10.0.0.1",
		}, token)
		assert.Equal(t, http.StatusCreated, resp.StatusCode)
		m := respJSON(t, resp)
		assert.Equal(t, "10.0.0.1", m["ip_address"])
	})

	t.Run("list with one", func(t *testing.T) {
		resp := env.get("/api/v1/settings/trusted-ips", token)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		m := respJSON(t, resp)
		data, _ := m["data"].([]any)
		assert.Len(t, data, 1)
	})

	t.Run("delete trusted ip", func(t *testing.T) {
		resp := env.del("/api/v1/settings/trusted-ips/10.0.0.1", token)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("list after delete", func(t *testing.T) {
		resp := env.get("/api/v1/settings/trusted-ips", token)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		m := respJSON(t, resp)
		data, _ := m["data"].([]any)
		assert.Empty(t, data)
	})

	t.Run("add empty ip", func(t *testing.T) {
		resp := env.post("/api/v1/settings/trusted-ips", map[string]string{
			"ip_address": "",
		}, token)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})
}

// ════════════════════════════════════════════════════════════════════
// Backup tests
// ════════════════════════════════════════════════════════════════════

func TestBackups(t *testing.T) {
	env := newTestEnv(t)
	token := env.rootToken()

	t.Run("list backups empty", func(t *testing.T) {
		resp := env.get("/api/v1/backups", token)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		m := respJSON(t, resp)
		assert.NotNil(t, m["data"])
	})

	t.Run("trigger backup", func(t *testing.T) {
		resp := env.post("/api/v1/backups/now", nil, token)
		assert.Equal(t, http.StatusAccepted, resp.StatusCode)
		m := respJSON(t, resp)
		assert.NotZero(t, m["job_id"])
		assert.Equal(t, "queued", m["status"])
	})

	t.Run("list backups with one", func(t *testing.T) {
		// Small wait for the backup to be inserted
		time.Sleep(100 * time.Millisecond)
		resp := env.get("/api/v1/backups", token)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		m := respJSON(t, resp)
		data, _ := m["data"].([]any)
		assert.GreaterOrEqual(t, len(data), 1)
	})

	t.Run("delete backup", func(t *testing.T) {
		// Trigger a backup first
		resp := env.post("/api/v1/backups/now", nil, token)
		require.Equal(t, http.StatusAccepted, resp.StatusCode)
		m := respJSON(t, resp)
		jobID := m["job_id"].(float64)

		resp = env.del(fmt.Sprintf("/api/v1/backups/%d", int64(jobID)), token)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("delete invalid id", func(t *testing.T) {
		resp := env.del("/api/v1/backups/0", token)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})
}

func TestBackupSettings(t *testing.T) {
	env := newTestEnv(t)
	token := env.rootToken()

	t.Run("get backup settings", func(t *testing.T) {
		resp := env.get("/api/v1/backups/settings", token)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		m := respJSON(t, resp)
		assert.NotNil(t, m["cron_expression"])
	})

	t.Run("update backup settings", func(t *testing.T) {
		resp := env.put("/api/v1/backups/settings", map[string]any{
			"cron_expression":       "0 4 * * *",
			"retention_count":       10,
			"retention_max_age_days": 30,
			"local_path":            "/tmp/backups",
		}, token)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		m := respJSON(t, resp)
		assert.Equal(t, true, m["ok"])
	})

	t.Run("verify updated settings", func(t *testing.T) {
		resp := env.get("/api/v1/backups/settings", token)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		m := respJSON(t, resp)
		assert.Equal(t, "0 4 * * *", m["cron_expression"])
	})
}

// ════════════════════════════════════════════════════════════════════
// Export tests
// ════════════════════════════════════════════════════════════════════

func TestExport(t *testing.T) {
	env := newTestEnv(t)
	token := env.rootToken()

	resp := env.post("/api/v1/export", nil, token)
	assert.Equal(t, http.StatusAccepted, resp.StatusCode)
	m := respJSON(t, resp)
	assert.NotZero(t, m["job_id"])
	assert.Equal(t, "queued", m["status"])
}

// ════════════════════════════════════════════════════════════════════
// Cross-cutting: pagination tests
// ════════════════════════════════════════════════════════════════════

func TestPagination(t *testing.T) {
	env := newTestEnv(t)
	token := env.rootToken()

	// Create several bans for pagination
	for i := 0; i < 5; i++ {
		env.post(fmt.Sprintf("/api/v1/users/paginate_pk_%d/ban", i),
			map[string]string{"reason": "pagination test"}, token)
	}

	t.Run("page 1", func(t *testing.T) {
		resp := env.get("/api/v1/bans/users?page=1&per_page=2", token)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		m := respJSON(t, resp)
		meta, _ := m["meta"].(map[string]any)
		assert.Equal(t, float64(2), meta["per_page"])
		assert.Equal(t, float64(1), meta["page"])
		total, _ := meta["total"].(float64)
		assert.GreaterOrEqual(t, total, float64(5))
	})

	t.Run("page 2", func(t *testing.T) {
		resp := env.get("/api/v1/bans/users?page=2&per_page=2", token)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		m := respJSON(t, resp)
		meta, _ := m["meta"].(map[string]any)
		assert.Equal(t, float64(2), meta["page"])
	})
}

// ════════════════════════════════════════════════════════════════════
// Auth middleware: all protected endpoints require auth
// ════════════════════════════════════════════════════════════════════

func TestAllEndpointsRequireAuth(t *testing.T) {
	env := newTestEnv(t)

	endpoints := []struct {
		method string
		path   string
	}{
		{"GET", "/api/v1/auth/me"},
		{"POST", "/api/v1/auth/logout"},
		{"GET", "/api/v1/invites"},
		{"POST", "/api/v1/invites"},
		{"GET", "/api/v1/admins"},
		{"GET", "/api/v1/sessions"},
		{"GET", "/api/v1/dashboard/metrics"},
		{"GET", "/api/v1/dashboard/charts/requests"},
		{"GET", "/api/v1/users"},
		{"GET", "/api/v1/users/pk123"},
		{"GET", "/api/v1/users/pk123/ips"},
		{"GET", "/api/v1/users/pk123/rooms"},
		{"GET", "/api/v1/users/pk123/chain"},
		{"GET", "/api/v1/users/pk123/bans"},
		{"POST", "/api/v1/users/pk123/ban"},
		{"POST", "/api/v1/users/pk123/unban"},
		{"GET", "/api/v1/users/pk123/room-bans"},
		{"PUT", "/api/v1/users/pk123/limits"},
		{"DELETE", "/api/v1/users/pk123/limits"},
		{"GET", "/api/v1/users/pk123/audit-log"},
		{"POST", "/api/v1/users/bulk/ban"},
		{"POST", "/api/v1/users/bulk/unban"},
		{"PUT", "/api/v1/users/bulk/limits"},
		{"GET", "/api/v1/bans/users"},
		{"GET", "/api/v1/bans/ips"},
		{"POST", "/api/v1/bans/ips"},
		{"GET", "/api/v1/bans/rooms"},
		{"GET", "/api/v1/rooms"},
		{"GET", "/api/v1/rooms/uuid123"},
		{"GET", "/api/v1/rooms/uuid123/participants"},
		{"GET", "/api/v1/rooms/uuid123/participants/online"},
		{"GET", "/api/v1/rooms/uuid123/ips"},
		{"GET", "/api/v1/rooms/uuid123/bans"},
		{"POST", "/api/v1/rooms/uuid123/ban"},
		{"POST", "/api/v1/rooms/uuid123/unban"},
		{"POST", "/api/v1/rooms/uuid123/ban-all-users"},
		{"GET", "/api/v1/rooms/uuid123/audit-log"},
		{"GET", "/api/v1/audit-log"},
		{"GET", "/api/v1/settings"},
		{"PATCH", "/api/v1/settings"},
		{"GET", "/api/v1/settings/trusted-ips"},
		{"POST", "/api/v1/settings/trusted-ips"},
		{"DELETE", "/api/v1/settings/trusted-ips/1.2.3.4"},
		{"GET", "/api/v1/backups"},
		{"POST", "/api/v1/backups/now"},
		{"DELETE", "/api/v1/backups/1"},
		{"GET", "/api/v1/backups/settings"},
		{"PUT", "/api/v1/backups/settings"},
		{"POST", "/api/v1/export"},
	}

	for _, ep := range endpoints {
		t.Run(ep.method+" "+ep.path, func(t *testing.T) {
			resp := env.do(ep.method, ep.path, nil, "")
			assert.Equal(t, http.StatusUnauthorized, resp.StatusCode,
				"%s %s should require auth", ep.method, ep.path)
			resp.Body.Close()
		})
	}
}

// Ensure unused import is referenced
var _ = assert.Equal
