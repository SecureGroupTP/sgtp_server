package admin

import "time"

type UserRole string

const (
	RoleRoot  UserRole = "root"
	RoleAdmin UserRole = "admin"
)

type AdminUser struct {
	ID                  int64     `json:"id"`
	LoginName           string    `json:"login_name"`
	DisplayName         string    `json:"display_name"`
	Role                UserRole  `json:"role"`
	ForcePasswordChange bool      `json:"force_password_change"`
	Disabled            bool      `json:"disabled"`
	CreatedAt           time.Time `json:"created_at"`
}

type AccessMode string

const (
	AccessOpen      AccessMode = "open"
	AccessWhitelist AccessMode = "whitelist"
	AccessPassword  AccessMode = "password"
	AccessKey       AccessMode = "key"
)

type AccessPolicy struct {
	Mode      AccessMode `json:"mode"`
	Whitelist []string   `json:"whitelist"`
	Password  string     `json:"password,omitempty"`
	SharedKey string     `json:"shared_key,omitempty"`
}

type UsageLimits struct {
	PerIP     map[string]int64 `json:"per_ip"`
	PerPubKey map[string]int64 `json:"per_pubkey"`
}

type BanRule struct {
	ID        int64      `json:"id"`
	Kind      string     `json:"kind"`
	Value     string     `json:"value"`
	Reason    string     `json:"reason"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

type BackupJob struct {
	ID           int64      `json:"id"`
	Status       string     `json:"status"`
	OutputPath   string     `json:"output_path,omitempty"`
	StartedAt    *time.Time `json:"started_at,omitempty"`
	FinishedAt   *time.Time `json:"finished_at,omitempty"`
	ErrorMessage string     `json:"error_message,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
}
