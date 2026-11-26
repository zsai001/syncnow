package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const relayVersion = "0.4.0"

var safeIDRegex = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,128}$`)

// Envelope matches SyncNowProtocol.WanRelayEnvelope.
// The relay never inspects plaintext; ciphertextBase64 is opaque ChaCha20-Poly1305 ciphertext.
type Envelope struct {
	ID               string  `json:"id"`
	Seq              int64   `json:"seq"`
	GroupHash        string  `json:"groupHash"`
	SenderDeviceID   string  `json:"senderDeviceID"`
	CreatedAtMs      int64   `json:"createdAtMs"`
	CiphertextBase64 string  `json:"ciphertextBase64"`
	BlobID           *string `json:"blobID,omitempty"`
	BlobSize         *int64  `json:"blobSize,omitempty"`
}

type groupState struct {
	NextSeq   int64      `json:"nextSeq"`
	Envelopes []Envelope `json:"envelopes"`
}

type wsClient struct {
	deviceID  string
	groupHash string
	ws        *wsConn
}

type authPrincipal struct {
	RoomID string
	User   *XTagsUser
	Mode   string // "xtags", "device_token", "static_token", "open"
}

type RelayServer struct {
	dataDir      string
	authToken    string
	adminToken   string
	maxEnvelopes int
	maxBlobBytes int64
	blobTTL      time.Duration

	cfgMu        sync.RWMutex
	cfg          DynamicRelayConfig
	xtags        *XTagsAuthVerifier
	adminXTags   *XTagsAuthVerifier
	signaling    *SignalingHub
	tunnels      *TunnelHub
	groupVault   *GroupKeyVaultStore
	tmpBlobs     *TmpBlobStore
	deviceTokens *DeviceTokenStore
	updates      *UpdateStore

	mu      sync.RWMutex
	groups  map[string]*groupState
	clients map[string]map[*wsClient]struct{}
}

func NewRelayServer(dataDir, authToken string, maxEnvelopes int, maxBlobBytes int64, blobTTL time.Duration) *RelayServer {
	return NewRelayServerWithOptions(dataDir, authToken, defaultXTagsAuthAPI, "", maxEnvelopes, maxBlobBytes, blobTTL)
}

func NewRelayServerWithOptions(
	dataDir, authToken, xtagsAuthAPI, allowUsersCSV string,
	maxEnvelopes int,
	maxBlobBytes int64,
	blobTTL time.Duration,
) *RelayServer {
	_ = os.MkdirAll(filepath.Join(dataDir, "groups"), 0o700)
	_ = os.MkdirAll(filepath.Join(dataDir, "blobs"), 0o700)

	s := &RelayServer{
		dataDir:      dataDir,
		authToken:    strings.TrimSpace(authToken),
		adminToken:   strings.TrimSpace(authToken),
		maxEnvelopes: maxEnvelopes,
		maxBlobBytes: maxBlobBytes,
		blobTTL:      blobTTL,
		signaling:    NewSignalingHub(),
		tunnels:      NewTunnelHub(),
		groupVault:   NewGroupKeyVaultStore(dataDir),
		tmpBlobs:     NewTmpBlobStore(dataDir),
		deviceTokens: NewDeviceTokenStore(dataDir),
		updates:      NewUpdateStore(dataDir),
		groups:       make(map[string]*groupState),
		clients:      make(map[string]map[*wsClient]struct{}),
	}
	s.initDynamicConfig(authToken, xtagsAuthAPI, allowUsersCSV)
	s.loadPersistedGroups()
	return s
}

func (s *RelayServer) Handler() http.Handler {
	mux := http.NewServeMux()
	// Zero-leak container / systemd liveness probe
	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})

	// Built-in Web Setup Wizard & Status Dashboard (`/` and `/setup`)
	mux.HandleFunc("/", s.handleSetupPage)
	mux.HandleFunc("/setup", s.handleSetupPage)
	mux.HandleFunc("/setup/", s.handleSetupPage)
	mux.HandleFunc("/favicon.ico", s.handleSetupPage)
	mux.HandleFunc("/v1/setup/status", s.handleSetupStatus)
	mux.HandleFunc("/v1/setup/relay-update", s.handleSetupRelayUpdate)
	mux.HandleFunc("/v1/setup/verify-xtags", s.handleSetupVerifyXTags)
	mux.HandleFunc("/v1/setup/complete", s.handleSetupComplete)
	mux.HandleFunc("/v1/setup/tmp-policy", s.handleSetupTmpPolicy)
	mux.HandleFunc("/v1/setup/purge-tmp", s.handleSetupPurgeTmp)
	mux.HandleFunc("/v1/setup/reset", s.handleSetupReset)

	// Scoped Revocable Device Tokens (`snr_dev_...`) for mobile / Mac App Store QR onboarding
	mux.HandleFunc("/v1/auth/device-tokens", s.handleDeviceTokens)
	mux.HandleFunc("/v1/auth/device-tokens/", s.handleDeviceTokens)

	// Core E2EE Clipboard, Legacy Blobs & Chunked Streaming Tmp Large Files
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/ws", s.handleWS)
	mux.HandleFunc("/v1/sync", s.handleSync)
	mux.HandleFunc("/v1/push", s.handlePush)
	mux.HandleFunc("/v1/blobs/", s.handleBlobs)
	mux.HandleFunc("/v1/tmp/", s.handleTmpRoutes)

	// Same-Account Peer Presence, Zero-Knowledge Group Key Vault & E2EE WebSocket Tunnel
	mux.HandleFunc("/v1/signal/ws", s.handleSignalWS)
	mux.HandleFunc("/v1/signal/peers", s.handleSignalPeers)
	mux.HandleFunc("/v1/signal/group-vault", s.handleSignalGroupVault)
	mux.HandleFunc("/v1/tunnel/ws", s.handleTunnelWS)

	// Auto-Update & Force-Update endpoints (used by release manifests & test harnesses)
	mux.HandleFunc("/v1/updates/check", s.handleUpdatesCheck)
	mux.HandleFunc("/v1/updates/files/", s.handleUpdateFiles)
	mux.HandleFunc("/v1/admin/updates", s.handleAdminUpdates)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if origin := r.Header.Get("Origin"); origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-SyncNow-Ticket, Range")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

// authenticateRequest verifies either:
// 1. Optional static `--token` (airgapped / private self-host fallback)
// 2. Scoped revocable device token `snr_dev_...` (mobile / QR onboarding)
// 3. Unified `xtags.top` Bearer token via `GET <auth-api>/v1/auth/me` (cached, with optional `--allow-user` owner lock)
// 4. Open mode ONLY if both `--token` and `--auth-api` are explicitly empty.
func (s *RelayServer) authenticateRequest(w http.ResponseWriter, r *http.Request) (*authPrincipal, bool) {
	got := extractBearerToken(r)

	s.cfgMu.RLock()
	staticToken := s.authToken
	xtagsVerifier := s.xtags
	s.cfgMu.RUnlock()

	// 1. Static token match (if configured)
	if staticToken != "" && got != "" && subtle.ConstantTimeCompare([]byte(got), []byte(staticToken)) == 1 {
		return &authPrincipal{RoomID: "static-owner", Mode: "static_token"}, true
	}

	// 2. Scoped device token (`snr_dev_...`)
	if strings.HasPrefix(got, deviceTokenPrefix) {
		if rec, ok := s.deviceTokens.Verify(got); ok {
			return &authPrincipal{RoomID: rec.RoomID, Mode: "device_token"}, true
		}
		writeAPIError(w, http.StatusUnauthorized, "unauthorized", "invalid or revoked device token")
		return nil, false
	}

	// 3. Unified xtags.top Bearer token verification
	if xtagsVerifier != nil && got != "" {
		user, status, err := xtagsVerifier.VerifyToken(r.Context(), got)
		if err != nil {
			code := "unauthorized"
			if status == http.StatusForbidden {
				code = "forbidden_account"
			}
			writeAPIError(w, status, code, err.Error())
			return nil, false
		}
		return &authPrincipal{RoomID: user.ID, User: user, Mode: "xtags"}, true
	}

	// 4. Explicit open mode (neither static token nor xtags auth API configured)
	if staticToken == "" && xtagsVerifier == nil {
		return &authPrincipal{RoomID: "open", Mode: "open"}, true
	}

	writeAPIError(w, http.StatusUnauthorized, "unauthorized", "valid xtags.top Bearer token or relay token is required")
	return nil, false
}

func (s *RelayServer) checkAuth(w http.ResponseWriter, r *http.Request) bool {
	_, ok := s.authenticateRequest(w, r)
	return ok
}

// authenticateRequestOrAdmin accepts either a normal client auth principal or the configured admin token
// (used by Web Console health probes and owner signaling peer inspection).
func (s *RelayServer) authenticateRequestOrAdmin(w http.ResponseWriter, r *http.Request) (*authPrincipal, bool) {
	got := extractBearerToken(r)
	cfg := s.currentConfig()
	if got != "" && cfg.AdminToken != "" && subtle.ConstantTimeCompare([]byte(got), []byte(cfg.AdminToken)) == 1 {
		roomID := cfg.OwnerUserID
		if roomID == "" {
			if cfg.AuthMode == "static_token" {
				roomID = "static-owner"
			} else {
				roomID = "admin"
			}
		}
		return &authPrincipal{RoomID: roomID, Mode: "admin_token"}, true
	}
	return s.authenticateRequest(w, r)
}

func (s *RelayServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.authenticateRequestOrAdmin(w, r)
	if !ok {
		return
	}

	cfg := s.currentConfig()
	s.cfgMu.RLock()
	xtagsVerifier := s.xtags
	s.cfgMu.RUnlock()

	var authUser map[string]any
	if principal.User != nil {
		authUser = map[string]any{
			"id":          principal.User.ID,
			"displayName": principal.User.DisplayName,
		}
	}

	caps := []string{
		"e2ee_relay",
		"e2ee_blobs",
		"tmp_chunked_blobs",
		"same_account_signaling",
		"group_key_vault",
		"ws_peer_tunnel",
		"device_tokens",
		"web_setup",
	}
	if xtagsVerifier != nil {
		caps = append(caps, "xtags_auth")
	}
	resp := map[string]any{
		"status":             "ok",
		"service":            "syncnow-relay",
		"runtime":            detectGoRuntimeName(),
		"storageBackend":     "disk",
		"version":            relayVersion,
		"initialized":        cfg.Initialized,
		"xtagsAuth":          xtagsVerifier != nil,
		"ownerLocked":        xtagsVerifier != nil && xtagsVerifier.HasAllowedUserFilter(),
		"authenticated":      principal.Mode != "open",
		"authMode":           principal.Mode,
		"maxBlobMB":          cfg.MaxBlobMB,
		"maxTmpFileMB":       cfg.MaxTmpFileMB,
		"maxTmpTotalMB":      cfg.MaxTmpTotalMB,
		"tmpTTLHours":        cfg.TmpTTLHours,
		"tmpAckGraceMinutes": cfg.TmpAckGraceMinutes,
		"tmpChunkPlainBytes": DefaultTmpChunkPlainBytes,
		"capabilities":       caps,
	}
	if authUser != nil {
		resp["user"] = authUser
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *RelayServer) handleWS(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}
	groupHash := r.URL.Query().Get("group")
	deviceID := r.URL.Query().Get("device")
	if !safeIDRegex.MatchString(groupHash) || !safeIDRegex.MatchString(deviceID) {
		http.Error(w, "invalid group or device", http.StatusBadRequest)
		return
	}

	ws, err := upgradeWebSocket(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	client := &wsClient{deviceID: deviceID, groupHash: groupHash, ws: ws}
	s.registerClient(client)
	defer func() {
		s.unregisterClient(client)
		_ = ws.Close()
	}()

	for {
		op, payload, err := ws.ReadMessage(2 * 1024 * 1024)
		if err != nil {
			return
		}
		if op != wsOpText && op != wsOpBinary {
			continue
		}
		var ctrl struct {
			Type string `json:"type"`
		}
		if json.Unmarshal(payload, &ctrl) == nil && ctrl.Type == "ping" {
			pong, _ := json.Marshal(map[string]any{
				"type":   "pong",
				"timeMs": time.Now().UnixMilli(),
			})
			_ = ws.WriteText(pong)
			continue
		}
		var env Envelope
		if err := json.Unmarshal(payload, &env); err != nil {
			continue
		}
		if env.GroupHash != groupHash {
			continue
		}
		env.SenderDeviceID = deviceID
		stored := s.appendEnvelope(groupHash, env)
		s.broadcastEnvelope(groupHash, deviceID, stored)
	}
}

func (s *RelayServer) handlePush(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var env Envelope
	if err := json.NewDecoder(io.LimitReader(r.Body, 2*1024*1024)).Decode(&env); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if !safeIDRegex.MatchString(env.GroupHash) || !safeIDRegex.MatchString(env.SenderDeviceID) {
		http.Error(w, "invalid groupHash or senderDeviceID", http.StatusBadRequest)
		return
	}
	stored := s.appendEnvelope(env.GroupHash, env)
	s.broadcastEnvelope(env.GroupHash, env.SenderDeviceID, stored)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(stored)
}

func (s *RelayServer) handleSync(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}
	groupHash := r.URL.Query().Get("group")
	if !safeIDRegex.MatchString(groupHash) {
		http.Error(w, "invalid group", http.StatusBadRequest)
		return
	}
	since, _ := strconv.ParseInt(r.URL.Query().Get("since"), 10, 64)
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 200 {
		limit = 100
	}

	s.mu.RLock()
	st := s.groups[groupHash]
	var out []Envelope
	if st != nil {
		for _, env := range st.Envelopes {
			if env.Seq > since {
				out = append(out, env)
				if len(out) >= limit {
					break
				}
			}
		}
	}
	s.mu.RUnlock()

	if out == nil {
		out = []Envelope{}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

func (s *RelayServer) handleBlobs(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}
	blobID := strings.TrimPrefix(r.URL.Path, "/v1/blobs/")
	groupHash := r.URL.Query().Get("group")
	if !safeIDRegex.MatchString(blobID) || !safeIDRegex.MatchString(groupHash) {
		http.Error(w, "invalid blobID or group", http.StatusBadRequest)
		return
	}

	dir := filepath.Join(s.dataDir, "blobs", groupHash)
	blobPath := filepath.Join(dir, blobID)

	switch r.Method {
	case http.MethodPost, http.MethodPut:
		if err := os.MkdirAll(dir, 0o700); err != nil {
			http.Error(w, "storage error", http.StatusInternalServerError)
			return
		}
		limited := io.LimitReader(r.Body, s.maxBlobBytes+1)
		data, err := io.ReadAll(limited)
		if err != nil {
			http.Error(w, "read failed", http.StatusBadRequest)
			return
		}
		if int64(len(data)) > s.maxBlobBytes {
			http.Error(w, "blob too large", http.StatusRequestEntityTooLarge)
			return
		}
		tmp := blobPath + ".tmp"
		if err := os.WriteFile(tmp, data, 0o600); err != nil {
			http.Error(w, "write failed", http.StatusInternalServerError)
			return
		}
		if err := os.Rename(tmp, blobPath); err != nil {
			http.Error(w, "commit failed", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusCreated)

	case http.MethodGet:
		data, err := os.ReadFile(blobPath)
		if err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(data)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *RelayServer) registerClient(c *wsClient) {
	s.mu.Lock()
	if s.clients[c.groupHash] == nil {
		s.clients[c.groupHash] = make(map[*wsClient]struct{})
	}
	var stale []*wsClient
	for existing := range s.clients[c.groupHash] {
		if existing != c && existing.deviceID == c.deviceID {
			stale = append(stale, existing)
			delete(s.clients[c.groupHash], existing)
		}
	}
	s.clients[c.groupHash][c] = struct{}{}
	s.mu.Unlock()

	for _, old := range stale {
		_ = old.ws.Close()
	}
}

func (s *RelayServer) unregisterClient(c *wsClient) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if set := s.clients[c.groupHash]; set != nil {
		delete(set, c)
		if len(set) == 0 {
			delete(s.clients, c.groupHash)
		}
	}
}

func (s *RelayServer) appendEnvelope(groupHash string, env Envelope) Envelope {
	s.mu.Lock()
	st := s.groups[groupHash]
	if st == nil {
		st = &groupState{}
		s.groups[groupHash] = st
	}
	st.NextSeq++
	env.Seq = st.NextSeq
	st.Envelopes = append(st.Envelopes, env)
	if len(st.Envelopes) > s.maxEnvelopes {
		st.Envelopes = st.Envelopes[len(st.Envelopes)-s.maxEnvelopes:]
	}
	snapshot, _ := json.Marshal(st)
	s.mu.Unlock()

	if len(snapshot) > 0 {
		path := filepath.Join(s.dataDir, "groups", groupHash+".json")
		tmp := path + ".tmp"
		if os.WriteFile(tmp, snapshot, 0o600) == nil {
			_ = os.Rename(tmp, path)
		}
	}
	return env
}

func (s *RelayServer) broadcastEnvelope(groupHash, senderDeviceID string, env Envelope) {
	raw, err := json.Marshal(env)
	if err != nil {
		return
	}
	s.mu.RLock()
	var targets []*wsClient
	for c := range s.clients[groupHash] {
		if c.deviceID != senderDeviceID {
			targets = append(targets, c)
		}
	}
	s.mu.RUnlock()

	for _, c := range targets {
		if err := c.ws.WriteText(raw); err != nil {
			_ = c.ws.Close()
		}
	}
}

func (s *RelayServer) loadPersistedGroups() {
	dir := filepath.Join(s.dataDir, "groups")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		groupHash := strings.TrimSuffix(entry.Name(), ".json")
		if !safeIDRegex.MatchString(groupHash) {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			continue
		}
		var st groupState
		if json.Unmarshal(raw, &st) == nil {
			s.groups[groupHash] = &st
		}
	}
}

func (s *RelayServer) StartCleanupLoop(stop <-chan struct{}) {
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			s.cleanupExpiredBlobs()
			s.tmpBlobs.CleanupExpired()
		}
	}
}

func (s *RelayServer) cleanupExpiredBlobs() {
	cutoff := time.Now().Add(-s.blobTTL)
	root := filepath.Join(s.dataDir, "blobs")
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if info, err := d.Info(); err == nil && info.ModTime().Before(cutoff) {
			_ = os.Remove(path)
		}
		return nil
	})
}

func main() {
	showVersion := flag.Bool("version", false, "Print relay version and exit")
	addr := flag.String("addr", envOrDefault("SYNCNOW_RELAY_ADDR", ":8787"), "Listen address")
	dataDir := flag.String("data-dir", envOrDefault("SYNCNOW_RELAY_DATA", "./data"), "Persistent data directory")
	authAPI := flag.String("auth-api", envOrDefault("SYNCNOW_AUTH_API", defaultXTagsAuthAPI), "xtags.top auth API base URL (empty to disable xtags auth)")
	allowUsers := flag.String("allow-user", os.Getenv("SYNCNOW_ALLOW_USERS"), "Optional comma-separated xtags user IDs allowed to use this self-hosted relay")
	token := flag.String("token", os.Getenv("SYNCNOW_RELAY_TOKEN"), "Optional static bearer auth token (for offline/airgapped mode)")
	adminToken := flag.String("admin-token", os.Getenv("SYNCNOW_ADMIN_TOKEN"), "Optional admin token for publishing release manifests (defaults to --token)")
	maxEnvelopes := flag.Int("max-envelopes", envIntOrDefault("SYNCNOW_MAX_ENVELOPES", 500), "Max retained encrypted envelopes per sync group")
	maxBlobMB := flag.Int64("max-blob-mb", envInt64OrDefault("SYNCNOW_MAX_BLOB_MB", 25), "Max encrypted blob size in MB")
	blobTTLDays := flag.Int("blob-ttl-days", envIntOrDefault("SYNCNOW_BLOB_TTL_DAYS", 7), "Retention days for encrypted blobs")
	flag.Parse()

	if *showVersion {
		fmt.Printf("syncnow-relay %s\n", relayVersion)
		return
	}

	relay := NewRelayServerWithOptions(
		*dataDir,
		*token,
		*authAPI,
		*allowUsers,
		*maxEnvelopes,
		*maxBlobMB*1024*1024,
		time.Duration(*blobTTLDays)*24*time.Hour,
	)
	if *adminToken != "" {
		relay.setAdminToken(*adminToken)
	}

	stop := make(chan struct{})
	defer close(stop)
	go relay.StartCleanupLoop(stop)

	log.Printf(
		"SyncNow Self-Hosted Relay v%s listening on %s (data=%s, xtagsAuth=%q, ownerLocked=%v, staticToken=%v)",
		relayVersion, *addr, *dataDir, *authAPI, *allowUsers != "", *token != "",
	)
	srv := &http.Server{
		Addr:              *addr,
		Handler:           relay.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-errCh:
		log.Fatalf("relay server exited: %v", err)
	case sig := <-sigCh:
		log.Printf("received %s, shutting down gracefully...", sig)
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envIntOrDefault(key string, fallback int) int {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return fallback
}

func envInt64OrDefault(key string, fallback int64) int64 {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			return n
		}
	}
	return fallback
}

func envIntAllowNegOrDefault(key string, fallback int) int {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= -1 {
			return n
		}
	}
	return fallback
}
