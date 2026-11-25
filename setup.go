package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	_ "embed"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

//go:embed setup_ui.html
var setupUIHTML []byte

// DynamicRelayConfig holds runtime settings manageable directly via the built-in Web Setup UI (`/` & `/setup`),
// persisted cleanly to `<dataDir>/config.json` (0600) so Docker/VPS users never have to edit env files manually!
type DynamicRelayConfig struct {
	Initialized      bool     `json:"initialized"`
	SiteName         string   `json:"siteName"`
	AuthMode         string   `json:"authMode"` // "xtags_owner" | "xtags_multi" | "static_token"
	AuthAPI          string   `json:"authAPI"`
	OwnerUserID      string   `json:"ownerUserID,omitempty"`
	OwnerDisplayName string   `json:"ownerDisplayName,omitempty"`
	AllowUsers       []string `json:"allowUsers"`
	StaticToken      string   `json:"staticToken,omitempty"`
	AdminToken       string   `json:"adminToken,omitempty"`
	MaxEnvelopes     int      `json:"maxEnvelopes"`
	MaxBlobMB        int64    `json:"maxBlobMB"`
	BlobTTLDays      int      `json:"blobTTLDays"`
	UpdatedAtMs      int64    `json:"updatedAtMs"`
}

func (s *RelayServer) configFilePath() string {
	return filepath.Join(s.dataDir, "config.json")
}

func (s *RelayServer) initDynamicConfig(authToken, xtagsAuthAPI, allowUsersCSV string) {
	allowList := splitCSV(allowUsersCSV)
	envConfigured := strings.TrimSpace(authToken) != "" || len(allowList) > 0

	mode := "xtags_owner"
	if strings.TrimSpace(authToken) != "" && strings.TrimSpace(xtagsAuthAPI) == "" {
		mode = "static_token"
	} else if len(allowList) == 0 && strings.TrimSpace(authToken) == "" {
		mode = "xtags_owner"
	}

	cfg := DynamicRelayConfig{
		Initialized:  envConfigured,
		SiteName:     "SyncNow Relay",
		AuthMode:     mode,
		AuthAPI:      strings.TrimRight(strings.TrimSpace(xtagsAuthAPI), "/"),
		AllowUsers:   allowList,
		StaticToken:  strings.TrimSpace(authToken),
		AdminToken:   strings.TrimSpace(s.adminToken),
		MaxEnvelopes: s.maxEnvelopes,
		MaxBlobMB:    maxInt64(1, s.maxBlobBytes/(1024*1024)),
		BlobTTLDays:  maxInt(1, int(s.blobTTL/(24*time.Hour))),
	}
	if len(allowList) > 0 {
		cfg.OwnerUserID = allowList[0]
	}

	// Overlay persisted web-setup config if present
	if raw, err := os.ReadFile(s.configFilePath()); err == nil {
		var disk DynamicRelayConfig
		if json.Unmarshal(raw, &disk) == nil {
			if strings.TrimSpace(disk.AdminToken) == "" && strings.TrimSpace(s.adminToken) != "" {
				disk.AdminToken = strings.TrimSpace(s.adminToken)
			}
			cfg = disk
		}
	}

	s.applyDynamicConfigLocked(cfg)
}

func (s *RelayServer) applyDynamicConfigLocked(cfg DynamicRelayConfig) {
	if cfg.SiteName == "" {
		cfg.SiteName = "SyncNow Relay"
	}
	if cfg.MaxEnvelopes <= 0 {
		cfg.MaxEnvelopes = 500
	}
	if cfg.MaxBlobMB <= 0 {
		cfg.MaxBlobMB = 25
	}
	if cfg.BlobTTLDays <= 0 {
		cfg.BlobTTLDays = 7
	}
	s.cfg = cfg
	s.maxEnvelopes = cfg.MaxEnvelopes
	s.maxBlobBytes = cfg.MaxBlobMB * 1024 * 1024
	s.blobTTL = time.Duration(cfg.BlobTTLDays) * 24 * time.Hour
	s.authToken = strings.TrimSpace(cfg.StaticToken)
	if strings.TrimSpace(cfg.AdminToken) != "" {
		s.adminToken = strings.TrimSpace(cfg.AdminToken)
	} else {
		s.adminToken = s.authToken
	}

	if cfg.AuthMode == "static_token" || strings.TrimSpace(cfg.AuthAPI) == "" {
		s.xtags = nil
		s.adminXTags = nil
	} else {
		allowCSV := ""
		if cfg.AuthMode == "xtags_owner" && len(cfg.AllowUsers) > 0 {
			allowCSV = strings.Join(cfg.AllowUsers, ",")
		}
		s.xtags = NewXTagsAuthVerifier(cfg.AuthAPI, allowCSV)
		s.adminXTags = NewXTagsAuthVerifier(cfg.AuthAPI, "")
	}
}

func (s *RelayServer) saveDynamicConfig(cfg DynamicRelayConfig) error {
	cfg.UpdatedAtMs = time.Now().UnixMilli()
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	path := s.configFilePath()
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	s.cfgMu.Lock()
	s.applyDynamicConfigLocked(cfg)
	s.cfgMu.Unlock()
	return nil
}

func (s *RelayServer) currentConfig() DynamicRelayConfig {
	s.cfgMu.RLock()
	defer s.cfgMu.RUnlock()
	c := s.cfg
	c.AllowUsers = append([]string(nil), s.cfg.AllowUsers...)
	return c
}

func (s *RelayServer) setAdminToken(tok string) {
	clean := strings.TrimSpace(tok)
	if clean == "" {
		return
	}
	s.cfgMu.Lock()
	s.cfg.AdminToken = clean
	s.adminToken = clean
	s.cfgMu.Unlock()
}

func (s *RelayServer) isRequestSetupAdmin(ctx context.Context, r *http.Request) bool {
	s.cfgMu.RLock()
	cfg := s.cfg
	adminVerifier := s.adminXTags
	s.cfgMu.RUnlock()

	got := extractBearerToken(r)
	if got == "" {
		return false
	}
	if cfg.AdminToken != "" && subtle.ConstantTimeCompare([]byte(got), []byte(cfg.AdminToken)) == 1 {
		return true
	}
	if cfg.StaticToken != "" && subtle.ConstantTimeCompare([]byte(got), []byte(cfg.StaticToken)) == 1 {
		return true
	}
	if cfg.AuthAPI != "" && cfg.OwnerUserID != "" {
		if adminVerifier == nil {
			adminVerifier = NewXTagsAuthVerifier(cfg.AuthAPI, "")
		}
		if user, _, err := adminVerifier.VerifyToken(ctx, got); err == nil && user != nil && user.ID == cfg.OwnerUserID {
			return true
		}
	}
	return false
}

func acceptsHTML(r *http.Request) bool {
	return strings.Contains(strings.ToLower(r.Header.Get("Accept")), "text/html")
}

// MARK: - HTTP Handlers for Built-In Web Setup UI

func (s *RelayServer) handleSetupPage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/favicon.ico" {
		w.Header().Set("Cache-Control", "public, max-age=86400")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.URL.Path == "/setup/" {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Robots-Tag", "noindex, nofollow")
		http.Redirect(w, r, "/setup", http.StatusFound)
		return
	}
	if r.URL.Path != "/" && r.URL.Path != "/setup" {
		if !s.checkAuth(w, r) {
			return
		}
		http.NotFound(w, r)
		return
	}
	if r.URL.Path == "/" {
		cfg := s.currentConfig()
		if !cfg.Initialized {
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("X-Robots-Tag", "noindex, nofollow")
			http.Redirect(w, r, "/setup", http.StatusFound)
			return
		}
		if !s.isRequestSetupAdmin(r.Context(), r) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="syncnow-relay"`)
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("X-Robots-Tag", "noindex, nofollow")
			// Browsers never send Authorization headers on top-level navigation to `/`:
			// serve the static zero-leak Web UI shell with HTTP 401 so already-unlocked
			// admin sessions render the dashboard and unauthenticated visitors see the unlock UI.
			if acceptsHTML(r) {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write(setupUIHTML)
				return
			}
			writeAPIError(w, http.StatusUnauthorized, "unauthorized", "authentication required")
			return
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(setupUIHTML)
}

func (s *RelayServer) handleSetupStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cfg := s.currentConfig()
	if !cfg.Initialized {
		writeJSON(w, http.StatusOK, map[string]any{
			"initialized":  false,
			"runtime":      "go-self-hosted",
			"version":      relayVersion,
			"siteName":     cfg.SiteName,
			"authMode":     cfg.AuthMode,
			"authAPI":      cfg.AuthAPI,
			"maxEnvelopes": cfg.MaxEnvelopes,
			"maxBlobMB":    cfg.MaxBlobMB,
			"blobTTLDays":  cfg.BlobTTLDays,
			"r2Enabled":    false,
			"isAdmin":      false,
		})
		return
	}
	if !s.isRequestSetupAdmin(r.Context(), r) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="syncnow-relay"`)
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"error":       "unauthorized",
			"message":     "admin authentication required",
			"initialized": true,
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"initialized":      true,
		"runtime":          "go-self-hosted",
		"version":          relayVersion,
		"siteName":         cfg.SiteName,
		"authMode":         cfg.AuthMode,
		"authAPI":          cfg.AuthAPI,
		"ownerDisplayName": cfg.OwnerDisplayName,
		"ownerUserID":      cfg.OwnerUserID,
		"ownerLocked":      cfg.AuthMode == "xtags_owner" && len(cfg.AllowUsers) > 0,
		"allowUsersCount":  len(cfg.AllowUsers),
		"allowUsers":       cfg.AllowUsers,
		"maxEnvelopes":     cfg.MaxEnvelopes,
		"maxBlobMB":        cfg.MaxBlobMB,
		"blobTTLDays":      cfg.BlobTTLDays,
		"r2Enabled":        false,
		"isAdmin":          true,
	})
}

const (
	relayRepoURL          = "https://github.com/zsai001/syncnow"
	relayDeployURL        = "https://xtags.top/deploy/syncnow"
	relayLatestPkgJSONURL = "https://raw.githubusercontent.com/zsai001/syncnow/main/package.json"
)

func (s *RelayServer) handleSetupRelayUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cfg := s.currentConfig()
	if cfg.Initialized && !s.isRequestSetupAdmin(r.Context(), r) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="syncnow-relay"`)
		w.Header().Set("Cache-Control", "no-store")
		writeAPIError(w, http.StatusUnauthorized, "unauthorized", "admin authentication required")
		return
	}

	resp := map[string]any{
		"currentVersion": relayVersion,
		"latestVersion":  relayVersion,
		"hasUpdate":      false,
		"runtime":        "go-self-hosted",
		"repoUrl":        relayRepoURL,
		"deployUrl":      relayDeployURL,
		"vpsUpgradeCmd":  "curl -fsSL https://raw.githubusercontent.com/zsai001/syncnow/main/deploy/vps-install.sh | sudo bash",
		"dockerUpgradeCmd": "git pull && docker compose up -d --build",
	}

	client := &http.Client{Timeout: 6 * time.Second}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, relayLatestPkgJSONURL, nil)
	if err == nil {
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Cache-Control", "no-cache")
		req.Header.Set("User-Agent", "syncnow-relay/"+relayVersion)
		if upResp, err := client.Do(req); err == nil {
			defer upResp.Body.Close()
			if upResp.StatusCode >= 200 && upResp.StatusCode < 300 {
				var pkg struct {
					Version string `json:"version"`
				}
				if json.NewDecoder(io.LimitReader(upResp.Body, 32*1024)).Decode(&pkg) == nil && strings.TrimSpace(pkg.Version) != "" {
					latest := strings.TrimSpace(pkg.Version)
					resp["latestVersion"] = latest
					resp["hasUpdate"] = compareSemVer(relayVersion, latest) < 0
				} else {
					resp["checkError"] = "invalid version metadata"
				}
			} else {
				resp["checkError"] = "upstream returned HTTP " + http.StatusText(upResp.StatusCode)
			}
		} else {
			resp["checkError"] = "unable to reach GitHub release metadata"
		}
	}

	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, resp)
}

func (s *RelayServer) handleSetupVerifyXTags(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cfg := s.currentConfig()
	var body struct {
		AuthCode string `json:"authCode"`
		Token    string `json:"token"`
		AuthAPI  string `json:"authAPI"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 32*1024)).Decode(&body); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_json", "invalid request body")
		return
	}
	if cfg.Initialized && cfg.AuthMode == "static_token" {
		writeAPIError(w, http.StatusUnauthorized, "unauthorized", "xtags admin login is disabled in static token mode")
		return
	}
	apiBase := strings.TrimRight(strings.TrimSpace(body.AuthAPI), "/")
	if cfg.Initialized {
		apiBase = strings.TrimRight(strings.TrimSpace(cfg.AuthAPI), "/")
	}
	if apiBase == "" {
		apiBase = defaultXTagsAuthAPI
	}

	user, token, status, errMsg := verifyOrExchangeXTags(r.Context(), apiBase, body.AuthCode, body.Token)
	if errMsg != "" {
		writeAPIError(w, status, "xtags_verify_failed", errMsg)
		return
	}
	if cfg.Initialized && (cfg.OwnerUserID == "" || user.ID != cfg.OwnerUserID) {
		writeAPIError(w, http.StatusUnauthorized, "unauthorized", "not authorized as relay administrator")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"token": token,
		"user":  user,
	})
}

func (s *RelayServer) handleSetupComplete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cfg := s.currentConfig()
	if cfg.Initialized && !s.isRequestSetupAdmin(r.Context(), r) {
		writeAPIError(w, http.StatusUnauthorized, "unauthorized", "admin authentication required to modify existing setup")
		return
	}

	var req struct {
		SiteName     string   `json:"siteName"`
		AuthMode     string   `json:"authMode"`
		AuthAPI      string   `json:"authAPI"`
		XTagsToken   string   `json:"xtagsToken"`
		AllowUsers   []string `json:"allowUsers"`
		StaticToken  string   `json:"staticToken"`
		AdminToken   string   `json:"adminToken"`
		MaxEnvelopes int      `json:"maxEnvelopes"`
		MaxBlobMB    int64    `json:"maxBlobMB"`
		BlobTTLDays  int      `json:"blobTTLDays"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 64*1024)).Decode(&req); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_json", "invalid json payload")
		return
	}

	mode := strings.TrimSpace(req.AuthMode)
	if mode != "xtags_owner" && mode != "xtags_multi" && mode != "static_token" {
		writeAPIError(w, http.StatusBadRequest, "invalid_mode", "authMode must be xtags_owner, xtags_multi, or static_token")
		return
	}

	next := cfg
	next.Initialized = true
	if strings.TrimSpace(req.SiteName) != "" {
		next.SiteName = strings.TrimSpace(req.SiteName)
	}
	next.AuthMode = mode
	if req.MaxEnvelopes > 0 && req.MaxEnvelopes <= 5000 {
		next.MaxEnvelopes = req.MaxEnvelopes
	}
	if req.MaxBlobMB > 0 && req.MaxBlobMB <= 512 {
		next.MaxBlobMB = req.MaxBlobMB
	}
	if req.BlobTTLDays > 0 && req.BlobTTLDays <= 365 {
		next.BlobTTLDays = req.BlobTTLDays
	}
	if strings.TrimSpace(req.AdminToken) != "" {
		next.AdminToken = strings.TrimSpace(req.AdminToken)
	}

	if mode == "static_token" {
		tok := strings.TrimSpace(req.StaticToken)
		if tok == "" {
			tok = cfg.StaticToken
		}
		if len(tok) < 12 {
			writeAPIError(w, http.StatusBadRequest, "weak_token", "staticToken must be at least 12 characters")
			return
		}
		next.StaticToken = tok
		next.AuthAPI = ""
		next.AllowUsers = nil
		next.OwnerUserID = ""
		next.OwnerDisplayName = ""
	} else {
		apiBase := strings.TrimRight(strings.TrimSpace(req.AuthAPI), "/")
		if apiBase == "" {
			apiBase = defaultXTagsAuthAPI
		}
		next.AuthAPI = apiBase
		next.StaticToken = ""

		tok := strings.TrimSpace(req.XTagsToken)
		if tok == "" {
			tok = extractBearerToken(r)
		}
		if tok != "" {
			user, _, status, errMsg := verifyOrExchangeXTags(r.Context(), apiBase, "", tok)
			if errMsg != "" {
				writeAPIError(w, status, "xtags_verify_failed", errMsg)
				return
			}
			next.OwnerUserID = user.ID
			next.OwnerDisplayName = user.DisplayName
		} else if !cfg.Initialized || next.OwnerUserID == "" {
			writeAPIError(w, http.StatusBadRequest, "owner_required", "valid xtags.top token is required to bind relay owner")
			return
		}

		if mode == "xtags_owner" {
			cleaned := dedupeStrings(req.AllowUsers)
			if len(cleaned) == 0 && next.OwnerUserID != "" {
				cleaned = []string{next.OwnerUserID}
			}
			next.AllowUsers = cleaned
		} else {
			next.AllowUsers = nil
		}
	}

	if err := s.saveDynamicConfig(next); err != nil {
		writeAPIError(w, http.StatusInternalServerError, "save_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *RelayServer) handleSetupReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.isRequestSetupAdmin(r.Context(), r) {
		writeAPIError(w, http.StatusUnauthorized, "unauthorized", "admin authentication required")
		return
	}
	_ = os.Remove(s.configFilePath())
	resetCfg := DynamicRelayConfig{
		Initialized:  false,
		SiteName:     "SyncNow Relay",
		AuthMode:     "xtags_owner",
		AuthAPI:      defaultXTagsAuthAPI,
		MaxEnvelopes: 500,
		MaxBlobMB:    25,
		BlobTTLDays:  7,
	}
	s.cfgMu.Lock()
	s.applyDynamicConfigLocked(resetCfg)
	s.cfgMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func verifyOrExchangeXTags(ctx context.Context, apiBase, authCode, rawToken string) (*XTagsUser, string, int, string) {
	client := &http.Client{Timeout: 8 * time.Second}
	code := strings.TrimSpace(strings.NewReplacer(" ", "", "-", "").Replace(authCode))
	if code != "" {
		payload, _ := json.Marshal(map[string]string{
			"code":  code,
			"label": "SyncNow Relay Setup",
		})
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiBase+"/v1/auth/syncnow-code/exchange", bytes.NewReader(payload))
		if err != nil {
			return nil, "", http.StatusBadRequest, err.Error()
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return nil, "", http.StatusBadGateway, "failed to reach xtags.top auth API"
		}
		defer resp.Body.Close()
		var parsed struct {
			Token string     `json:"token"`
			User  *XTagsUser `json:"user"`
			Error string     `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&parsed)
		if resp.StatusCode < 200 || resp.StatusCode >= 300 || parsed.User == nil || parsed.Token == "" {
			msg := parsed.Error
			if msg == "" {
				msg = "invalid or expired 6-digit code"
			}
			return nil, "", http.StatusBadRequest, msg
		}
		return parsed.User, parsed.Token, http.StatusOK, ""
	}

	tok := strings.TrimSpace(rawToken)
	if tok == "" {
		return nil, "", http.StatusBadRequest, "authCode or token is required"
	}
	v := NewXTagsAuthVerifier(apiBase, "")
	user, status, err := v.VerifyToken(ctx, tok)
	if err != nil || user == nil {
		return nil, "", status, "xtags.top token is invalid or expired"
	}
	return user, tok, http.StatusOK, ""
}

func splitCSV(csv string) []string {
	var out []string
	for _, p := range strings.Split(csv, ",") {
		t := strings.TrimSpace(p)
		if t != "" {
			out = append(out, t)
		}
	}
	return dedupeStrings(out)
}

func dedupeStrings(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	var out []string
	for _, v := range in {
		t := strings.TrimSpace(v)
		if t == "" {
			continue
		}
		if _, ok := seen[t]; !ok {
			seen[t] = struct{}{}
			out = append(out, t)
		}
	}
	return out
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
