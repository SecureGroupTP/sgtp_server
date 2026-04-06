package admin

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func HashPassword(password string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(h), nil
}

func CheckPassword(hash string, password string) (bool, error) {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err == nil {
		return true, nil
	}
	if err == bcrypt.ErrMismatchedHashAndPassword {
		return false, nil
	}
	return false, err
}

func RandomToken(n int) (string, error) {
	if n <= 0 {
		n = 32
	}
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func BuildJWT(secret []byte, userID int64, role UserRole, ttl time.Duration) (string, error) {
	now := time.Now().UTC()
	headerRaw, _ := json.Marshal(map[string]any{"alg": "HS256", "typ": "JWT"})
	payloadRaw, _ := json.Marshal(map[string]any{
		"sub":  strconv.FormatInt(userID, 10),
		"role": string(role),
		"iat":  now.Unix(),
		"exp":  now.Add(ttl).Unix(),
	})
	hdr := base64.RawURLEncoding.EncodeToString(headerRaw)
	pl := base64.RawURLEncoding.EncodeToString(payloadRaw)
	msg := hdr + "." + pl
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(msg))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return msg + "." + sig, nil
}

func ParseAndVerifyJWT(secret []byte, token string) (int64, UserRole, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return 0, "", fmt.Errorf("invalid token")
	}
	msg := parts[0] + "." + parts[1]
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(msg))
	expected := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(expected), []byte(parts[2])) {
		return 0, "", fmt.Errorf("bad signature")
	}
	payloadRaw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return 0, "", err
	}
	var payload struct {
		Sub  string `json:"sub"`
		Role string `json:"role"`
		Exp  int64  `json:"exp"`
	}
	if err := json.Unmarshal(payloadRaw, &payload); err != nil {
		return 0, "", err
	}
	if payload.Exp < time.Now().UTC().Unix() {
		return 0, "", fmt.Errorf("expired token")
	}
	uid, err := strconv.ParseInt(payload.Sub, 10, 64)
	if err != nil {
		return 0, "", err
	}
	return uid, UserRole(payload.Role), nil
}
