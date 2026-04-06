package admin

import (
	"testing"
	"time"
)

func TestPasswordHashAndCheck(t *testing.T) {
	h, err := HashPassword("secret123")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	ok, err := CheckPassword(h, "secret123")
	if err != nil {
		t.Fatalf("CheckPassword: %v", err)
	}
	if !ok {
		t.Fatalf("expected password match")
	}
	ok, err = CheckPassword(h, "wrong")
	if err != nil {
		t.Fatalf("CheckPassword wrong: %v", err)
	}
	if ok {
		t.Fatalf("expected password mismatch")
	}
}

func TestJWTBuildAndParse(t *testing.T) {
	secret := []byte("test-secret")
	tok, err := BuildJWT(secret, 42, RoleRoot, 5*time.Minute)
	if err != nil {
		t.Fatalf("BuildJWT: %v", err)
	}
	uid, role, err := ParseAndVerifyJWT(secret, tok)
	if err != nil {
		t.Fatalf("ParseAndVerifyJWT: %v", err)
	}
	if uid != 42 {
		t.Fatalf("uid=%d want=42", uid)
	}
	if role != RoleRoot {
		t.Fatalf("role=%s want=%s", role, RoleRoot)
	}
}

func TestJWTExpired(t *testing.T) {
	secret := []byte("test-secret")
	tok, err := BuildJWT(secret, 7, RoleAdmin, -1*time.Minute)
	if err != nil {
		t.Fatalf("BuildJWT: %v", err)
	}
	if _, _, err := ParseAndVerifyJWT(secret, tok); err == nil {
		t.Fatalf("expected expired token error")
	}
}
