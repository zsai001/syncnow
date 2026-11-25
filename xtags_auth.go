package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	defaultXTagsAuthAPI    = "https://api.xtags.top"
	xtagsCacheValidTTL     = 5 * time.Minute
	xtagsCacheInvalidTTL   = 15 * time.Second
	xtagsVerifyHTTPTimeout = 6 * time.Second
	maxAuthBodyBytes       = 256 * 1024
)

type XTagsUser struct {
	ID          string   `json:"id"`
	Email       *string  `json:"email,omitempty"`
	DisplayName string   `json:"displayName"`
	AvatarURL   *string  `json:"avatarUrl,omitempty"`
	Role        string   `json:"role,omitempty"`
	Providers   []string `json:"providers,omitempty"`
}

type xtagsMeResponse struct {
	Authenticated bool       `json:"authenticated"`
	User          *XTagsUser `json:"user"`
}

type cachedXTagsResult struct {
	user      *XTagsUser
	valid     bool
	expiresAt time.Time
}

// XTagsAuthVerifier validates `xtags_ext_...` / `xtags_web_...` Bearer tokens against `api.xtags.top/v1/auth/me`
// with short-lived in-memory caching and optional `--allow-user` owner restriction.
type XTagsAuthVerifier struct {
	apiBaseURL   string
	allowedUsers map[string]struct{}
	httpClient   *http.Client

	mu    sync.RWMutex
	cache map[string]cachedXTagsResult
}

func NewXTagsAuthVerifier(apiBaseURL string, allowedUserCSV string) *XTagsAuthVerifier {
	clean := strings.TrimRight(strings.TrimSpace(apiBaseURL), "/")
	if clean == "" {
		return nil
	}
	allowed := make(map[string]struct{})
	for _, item := range strings.Split(allowedUserCSV, ",") {
		trimmed := strings.TrimSpace(item)
		if trimmed != "" {
			allowed[trimmed] = struct{}{}
		}
	}
	return &XTagsAuthVerifier{
		apiBaseURL:   clean,
		allowedUsers: allowed,
		httpClient:   &http.Client{Timeout: xtagsVerifyHTTPTimeout},
		cache:        make(map[string]cachedXTagsResult),
	}
}

func (v *XTagsAuthVerifier) HasAllowedUserFilter() bool {
	return v != nil && len(v.allowedUsers) > 0
}

func (v *XTagsAuthVerifier) isUserAllowed(userID string) bool {
	if len(v.allowedUsers) == 0 {
		return true
	}
	_, ok := v.allowedUsers[userID]
	return ok
}

func hashTokenKey(rawToken string) string {
	sum := sha256.Sum256([]byte(rawToken))
	return hex.EncodeToString(sum[:])
}

// VerifyToken checks the Bearer token via cache or `GET <apiBaseURL>/v1/auth/me`.
// Returns (user, httpStatus, err).
func (v *XTagsAuthVerifier) VerifyToken(ctx context.Context, rawToken string) (*XTagsUser, int, error) {
	if v == nil {
		return nil, http.StatusUnauthorized, errors.New("xtags auth verifier disabled")
	}
	tok := strings.TrimSpace(rawToken)
	if tok == "" {
		return nil, http.StatusUnauthorized, errors.New("missing bearer token")
	}

	key := hashTokenKey(tok)
	now := time.Now()

	v.mu.RLock()
	cached, ok := v.cache[key]
	v.mu.RUnlock()
	if ok && now.Before(cached.expiresAt) {
		if !cached.valid || cached.user == nil {
			return nil, http.StatusUnauthorized, errors.New("invalid or expired xtags token")
		}
		if !v.isUserAllowed(cached.user.ID) {
			return nil, http.StatusForbidden, errors.New("xtags account is not allowed on this self-hosted relay")
		}
		userCopy := *cached.user
		return &userCopy, http.StatusOK, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.apiBaseURL+"/v1/auth/me", nil)
	if err != nil {
		return nil, http.StatusBadGateway, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "application/json")

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return nil, http.StatusBadGateway, errors.New("failed to reach xtags auth api")
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		v.putCache(key, cachedXTagsResult{valid: false, expiresAt: now.Add(xtagsCacheInvalidTTL)})
		return nil, http.StatusUnauthorized, errors.New("xtags token rejected")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, http.StatusBadGateway, errors.New("xtags auth api returned error")
	}

	var parsed xtagsMeResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, http.StatusBadGateway, errors.New("invalid xtags auth response")
	}
	if !parsed.Authenticated || parsed.User == nil || strings.TrimSpace(parsed.User.ID) == "" {
		v.putCache(key, cachedXTagsResult{valid: false, expiresAt: now.Add(xtagsCacheInvalidTTL)})
		return nil, http.StatusUnauthorized, errors.New("xtags token not authenticated")
	}

	userCopy := *parsed.User
	v.putCache(key, cachedXTagsResult{
		user:      &userCopy,
		valid:     true,
		expiresAt: now.Add(xtagsCacheValidTTL),
	})

	if !v.isUserAllowed(userCopy.ID) {
		return nil, http.StatusForbidden, errors.New("xtags account is not allowed on this self-hosted relay")
	}
	return &userCopy, http.StatusOK, nil
}

func (v *XTagsAuthVerifier) putCache(key string, entry cachedXTagsResult) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if len(v.cache) > 2048 {
		now := time.Now()
		for k, item := range v.cache {
			if now.After(item.expiresAt) {
				delete(v.cache, k)
			}
		}
	}
	v.cache[key] = entry
}

// MARK: - Shared HTTP Helpers

func extractBearerToken(r *http.Request) string {
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
	}
	return strings.TrimSpace(r.URL.Query().Get("token"))
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeAPIError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{
		"error":   code,
		"message": message,
	})
}
