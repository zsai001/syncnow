package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const deviceTokenPrefix = "snr_dev_"

type DeviceTokenRecord struct {
	ID           string `json:"id"`
	Label        string `json:"label"`
	TokenHash    string `json:"tokenHash"`
	TokenPreview string `json:"tokenPreview"`
	RoomID       string `json:"roomID"`
	CreatedAtMs  int64  `json:"createdAtMs"`
	ExpiresAtMs  int64  `json:"expiresAtMs,omitempty"`
	LastUsedAtMs int64  `json:"lastUsedAtMs,omitempty"`
}

type DeviceTokenStore struct {
	filePath string
	mu       sync.RWMutex
	tokens   []DeviceTokenRecord
}

func NewDeviceTokenStore(dataDir string) *DeviceTokenStore {
	s := &DeviceTokenStore{
		filePath: filepath.Join(dataDir, "device_tokens.json"),
	}
	s.load()
	return s
}

func (s *DeviceTokenStore) load() {
	raw, err := os.ReadFile(s.filePath)
	if err != nil {
		return
	}
	var list []DeviceTokenRecord
	if json.Unmarshal(raw, &list) == nil {
		s.tokens = list
	}
}

func (s *DeviceTokenStore) saveLocked() error {
	raw, err := json.MarshalIndent(s.tokens, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.filePath + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.filePath)
}

func hashDeviceToken(raw string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(raw)))
	return hex.EncodeToString(sum[:])
}

func (s *DeviceTokenStore) Issue(label, roomID string, ttlDays int) (string, DeviceTokenRecord, error) {
	if strings.TrimSpace(label) == "" {
		label = "Mobile / QR Device"
	}
	if strings.TrimSpace(roomID) == "" {
		roomID = "static-owner"
	}
	var rnd [24]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return "", DeviceTokenRecord{}, err
	}
	rawToken := deviceTokenPrefix + hex.EncodeToString(rnd[:])
	var idBytes [8]byte
	_, _ = rand.Read(idBytes[:])
	id := "dt_" + hex.EncodeToString(idBytes[:])

	now := time.Now().UnixMilli()
	var exp int64
	if ttlDays > 0 {
		exp = now + int64(ttlDays)*24*60*60*1000
	}
	preview := rawToken[:14] + "…" + rawToken[len(rawToken)-4:]

	rec := DeviceTokenRecord{
		ID:           id,
		Label:        strings.TrimSpace(label),
		TokenHash:    hashDeviceToken(rawToken),
		TokenPreview: preview,
		RoomID:       roomID,
		CreatedAtMs:  now,
		ExpiresAtMs:  exp,
	}

	s.mu.Lock()
	// Cap maximum retained device tokens to 64 (evict oldest if exceeded)
	if len(s.tokens) >= 64 {
		s.tokens = s.tokens[len(s.tokens)-63:]
	}
	s.tokens = append(s.tokens, rec)
	err := s.saveLocked()
	s.mu.Unlock()
	return rawToken, rec, err
}

func (s *DeviceTokenStore) Verify(rawToken string) (*DeviceTokenRecord, bool) {
	clean := strings.TrimSpace(rawToken)
	if !strings.HasPrefix(clean, deviceTokenPrefix) {
		return nil, false
	}
	wantHash := hashDeviceToken(clean)
	now := time.Now().UnixMilli()

	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.tokens {
		rec := &s.tokens[i]
		if subtle.ConstantTimeCompare([]byte(rec.TokenHash), []byte(wantHash)) == 1 {
			if rec.ExpiresAtMs > 0 && now >= rec.ExpiresAtMs {
				return nil, false
			}
			if now-rec.LastUsedAtMs > 60_000 {
				rec.LastUsedAtMs = now
				_ = s.saveLocked()
			}
			out := *rec
			out.TokenHash = ""
			return &out, true
		}
	}
	return nil, false
}

func (s *DeviceTokenStore) ListPublic() []DeviceTokenRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]DeviceTokenRecord, 0, len(s.tokens))
	for _, r := range s.tokens {
		cp := r
		cp.TokenHash = ""
		out = append(out, cp)
	}
	return out
}

func (s *DeviceTokenStore) Revoke(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	idx := -1
	for i := range s.tokens {
		if s.tokens[i].ID == id {
			idx = i
			break
		}
	}
	if idx < 0 {
		return false
	}
	s.tokens = append(s.tokens[:idx], s.tokens[idx+1:]...)
	_ = s.saveLocked()
	return true
}

func (s *DeviceTokenStore) ClearAll() {
	s.mu.Lock()
	s.tokens = nil
	_ = os.Remove(s.filePath)
	s.mu.Unlock()
}

// HTTP handlers on RelayServer for `/v1/auth/device-tokens` and `/v1/auth/device-tokens/<id>`

func (s *RelayServer) handleDeviceTokens(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if strings.HasPrefix(path, "/v1/auth/device-tokens/") {
		if r.Method != http.MethodDelete {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !s.isRequestSetupAdmin(r.Context(), r) {
			writeAPIError(w, http.StatusUnauthorized, "unauthorized", "admin authentication required to revoke device token")
			return
		}
		id := strings.TrimPrefix(path, "/v1/auth/device-tokens/")
		if !safeIDRegex.MatchString(id) {
			writeAPIError(w, http.StatusBadRequest, "invalid_id", "invalid token id")
			return
		}
		ok := s.deviceTokens.Revoke(id)
		writeJSON(w, http.StatusOK, map[string]any{"ok": ok})
		return
	}

	switch r.Method {
	case http.MethodGet:
		if !s.isRequestSetupAdmin(r.Context(), r) {
			writeAPIError(w, http.StatusUnauthorized, "unauthorized", "admin authentication required")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"tokens": s.deviceTokens.ListPublic(),
		})

	case http.MethodPost:
		// Either setup admin OR an authenticated non-device_token principal (e.g. xtags desktop client generating QR) may mint a scoped device token.
		var roomID string
		if s.isRequestSetupAdmin(r.Context(), r) {
			cfg := s.currentConfig()
			roomID = cfg.OwnerUserID
			if roomID == "" {
				roomID = "static-owner"
			}
		} else {
			principal, ok := s.authenticateRequest(w, r)
			if !ok {
				return
			}
			if principal.Mode == "device_token" || principal.Mode == "open" {
				writeAPIError(w, http.StatusForbidden, "forbidden", "scoped device tokens cannot mint new tokens")
				return
			}
			roomID = principal.RoomID
		}

		var req struct {
			Label   string `json:"label"`
			TTLDays int    `json:"ttlDays"`
		}
		_ = json.NewDecoder(io.LimitReader(r.Body, 16*1024)).Decode(&req)
		if req.TTLDays < 0 || req.TTLDays > 3650 {
			req.TTLDays = 0
		}
		rawTok, rec, err := s.deviceTokens.Issue(req.Label, roomID, req.TTLDays)
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, "issue_failed", err.Error())
			return
		}
		rec.TokenHash = ""
		writeJSON(w, http.StatusOK, map[string]any{
			"token":  rawTok,
			"record": rec,
		})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
