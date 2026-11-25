package main

import (
	"crypto/subtle"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ReleaseEntry represents the published update policy & artifact for a platform+arch+channel target.
type ReleaseEntry struct {
	Platform           string            `json:"platform"`                     // macos, ios, windows, linux, android
	Arch               string            `json:"arch"`                         // arm64, x86_64, universal
	Channel            string            `json:"channel"`                      // stable, beta
	LatestVersion      string            `json:"latestVersion"`                // SemVer e.g. "0.2.0"
	LatestBuild        int               `json:"latestBuild"`                  // Monotonic build number
	MinRequiredVersion string            `json:"minRequiredVersion"`           // Versions below this trigger FORCE UPDATE
	MinRequiredBuild   int               `json:"minRequiredBuild"`             // Optional build floor when version == minRequiredVersion
	ForceUpdate        bool              `json:"forceUpdate"`                  // Explicit force flag for all versions < latest
	DownloadURL        string            `json:"downloadURL"`                  // Absolute URL or relative "/v1/updates/files/..."
	SHA256             string            `json:"sha256"`                       // Lowercase hex SHA-256 of the downloaded archive
	Ed25519Signature   string            `json:"ed25519Signature,omitempty"`   // Base64 Ed25519 signature over SHA-256 hex string
	FileSizeBytes      int64             `json:"fileSizeBytes"`
	ReleaseNotes       map[string]string `json:"releaseNotes"`                 // e.g. {"zh-Hans": "...", "en": "..."}
	PublishedAtMs      int64             `json:"publishedAtMs"`
}

type UpdateCheckResponse struct {
	HasUpdate          bool              `json:"hasUpdate"`
	ForceUpdate        bool              `json:"forceUpdate"`
	CurrentVersion     string            `json:"currentVersion"`
	CurrentBuild       int               `json:"currentBuild"`
	LatestVersion      string            `json:"latestVersion"`
	LatestBuild        int               `json:"latestBuild"`
	MinRequiredVersion string            `json:"minRequiredVersion"`
	MinRequiredBuild   int               `json:"minRequiredBuild"`
	DownloadURL        string            `json:"downloadURL"`
	SHA256             string            `json:"sha256"`
	Ed25519Signature   string            `json:"ed25519Signature,omitempty"`
	FileSizeBytes      int64             `json:"fileSizeBytes"`
	ReleaseNotes       map[string]string `json:"releaseNotes"`
	PublishedAtMs      int64             `json:"publishedAtMs"`
}

type UpdateManifest struct {
	Releases  []ReleaseEntry `json:"releases"`
	UpdatedAt int64          `json:"updatedAtMs"`
}

type UpdateStore struct {
	manifestPath string
	filesDir     string

	mu       sync.RWMutex
	manifest UpdateManifest
}

func NewUpdateStore(dataDir string) *UpdateStore {
	updatesDir := filepath.Join(dataDir, "updates")
	filesDir := filepath.Join(updatesDir, "files")
	_ = os.MkdirAll(filesDir, 0o755)
	u := &UpdateStore{
		manifestPath: filepath.Join(updatesDir, "manifest.json"),
		filesDir:     filesDir,
		manifest:     UpdateManifest{Releases: []ReleaseEntry{}},
	}
	u.load()
	return u
}

func (u *UpdateStore) load() {
	raw, err := os.ReadFile(u.manifestPath)
	if err != nil {
		return
	}
	var m UpdateManifest
	if json.Unmarshal(raw, &m) == nil {
		u.manifest = m
	}
}

func (u *UpdateStore) SaveManifest(m UpdateManifest) error {
	if m.UpdatedAt == 0 {
		m.UpdatedAt = time.Now().UnixMilli()
	}
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	u.mu.Lock()
	u.manifest = m
	u.mu.Unlock()

	tmp := u.manifestPath + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, u.manifestPath)
}

func (u *UpdateStore) UpsertRelease(entry ReleaseEntry) error {
	if entry.Channel == "" {
		entry.Channel = "stable"
	}
	if entry.Arch == "" {
		entry.Arch = "universal"
	}
	if entry.PublishedAtMs == 0 {
		entry.PublishedAtMs = time.Now().UnixMilli()
	}
	u.mu.Lock()
	m := u.manifest
	replaced := false
	for i := range m.Releases {
		r := m.Releases[i]
		if strings.EqualFold(r.Platform, entry.Platform) &&
			strings.EqualFold(r.Arch, entry.Arch) &&
			strings.EqualFold(r.Channel, entry.Channel) {
			m.Releases[i] = entry
			replaced = true
			break
		}
	}
	if !replaced {
		m.Releases = append(m.Releases, entry)
	}
	m.UpdatedAt = time.Now().UnixMilli()
	u.manifest = m
	raw, err := json.MarshalIndent(m, "", "  ")
	u.mu.Unlock()
	if err != nil {
		return err
	}
	tmp := u.manifestPath + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, u.manifestPath)
}

func (u *UpdateStore) FindRelease(platform, arch, channel string) *ReleaseEntry {
	if channel == "" {
		channel = "stable"
	}
	u.mu.RLock()
	defer u.mu.RUnlock()

	var universalFallback *ReleaseEntry
	for i := range u.manifest.Releases {
		r := u.manifest.Releases[i]
		if !strings.EqualFold(r.Platform, platform) || !strings.EqualFold(r.Channel, channel) {
			continue
		}
		if strings.EqualFold(r.Arch, arch) {
			cp := r
			return &cp
		}
		if strings.EqualFold(r.Arch, "universal") || r.Arch == "" {
			cp := r
			universalFallback = &cp
		}
	}
	return universalFallback
}

// compareSemVer compares two dotted semantic versions (e.g. "0.2.1" vs "0.10.0").
// Returns -1 if a < b, 0 if a == b, +1 if a > b.
func compareSemVer(a, b string) int {
	pa := parseSemVerParts(a)
	pb := parseSemVerParts(b)
	for i := 0; i < 3; i++ {
		if pa[i] < pb[i] {
			return -1
		}
		if pa[i] > pb[i] {
			return 1
		}
	}
	return 0
}

func parseSemVerParts(v string) [3]int {
	v = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(v, "v"), "V"))
	if idx := strings.IndexAny(v, "-+"); idx >= 0 {
		v = v[:idx]
	}
	parts := strings.Split(v, ".")
	var out [3]int
	for i := 0; i < 3 && i < len(parts); i++ {
		n, _ := strconv.Atoi(parts[i])
		out[i] = n
	}
	return out
}

func isVersionBelow(curVer string, curBuild int, targetVer string, targetBuild int) bool {
	if strings.TrimSpace(targetVer) == "" {
		return false
	}
	cmp := compareSemVer(curVer, targetVer)
	if cmp < 0 {
		return true
	}
	if cmp > 0 {
		return false
	}
	if targetBuild > 0 && curBuild > 0 {
		return curBuild < targetBuild
	}
	return false
}

func resolveDownloadURL(r *http.Request, raw string) string {
	if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") || raw == "" {
		return raw
	}
	scheme := "http"
	if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		scheme = "https"
	}
	if !strings.HasPrefix(raw, "/") {
		raw = "/" + raw
	}
	return scheme + "://" + r.Host + raw
}

func (s *RelayServer) handleUpdatesCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeAPIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "GET required")
		return
	}
	platform := strings.TrimSpace(r.URL.Query().Get("platform"))
	if platform == "" {
		platform = "macos"
	}
	arch := strings.TrimSpace(r.URL.Query().Get("arch"))
	if arch == "" {
		arch = "arm64"
	}
	channel := strings.TrimSpace(r.URL.Query().Get("channel"))
	if channel == "" {
		channel = "stable"
	}
	curVer := strings.TrimSpace(r.URL.Query().Get("version"))
	if curVer == "" {
		curVer = "0.0.0"
	}
	curBuild, _ := strconv.Atoi(r.URL.Query().Get("build"))

	rel := s.updates.FindRelease(platform, arch, channel)
	if rel == nil {
		writeJSON(w, http.StatusOK, UpdateCheckResponse{
			HasUpdate:      false,
			ForceUpdate:    false,
			CurrentVersion: curVer,
			CurrentBuild:   curBuild,
			LatestVersion:  curVer,
			LatestBuild:    curBuild,
			ReleaseNotes:   map[string]string{},
		})
		return
	}

	hasUpdate := isVersionBelow(curVer, curBuild, rel.LatestVersion, rel.LatestBuild)
	belowMin := isVersionBelow(curVer, curBuild, rel.MinRequiredVersion, rel.MinRequiredBuild)
	forceUpdate := hasUpdate && (rel.ForceUpdate || belowMin)
	// Even if latestVersion == minRequiredVersion and client is strictly below minRequired, ensure hasUpdate=true
	if belowMin {
		hasUpdate = true
		forceUpdate = true
	}

	notes := rel.ReleaseNotes
	if notes == nil {
		notes = map[string]string{}
	}

	writeJSON(w, http.StatusOK, UpdateCheckResponse{
		HasUpdate:          hasUpdate,
		ForceUpdate:        forceUpdate,
		CurrentVersion:     curVer,
		CurrentBuild:       curBuild,
		LatestVersion:      rel.LatestVersion,
		LatestBuild:        rel.LatestBuild,
		MinRequiredVersion: rel.MinRequiredVersion,
		MinRequiredBuild:   rel.MinRequiredBuild,
		DownloadURL:        resolveDownloadURL(r, rel.DownloadURL),
		SHA256:             rel.SHA256,
		Ed25519Signature:   rel.Ed25519Signature,
		FileSizeBytes:      rel.FileSizeBytes,
		ReleaseNotes:       notes,
		PublishedAtMs:      rel.PublishedAtMs,
	})
}

func (s *RelayServer) handleUpdateFiles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeAPIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "GET required")
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/v1/updates/files/")
	if name == "" || strings.Contains(name, "/") || strings.Contains(name, "..") || !safeIDRegex.MatchString(name) {
		writeAPIError(w, http.StatusBadRequest, "invalid_filename", "Invalid release file name")
		return
	}
	fullPath := filepath.Join(s.updates.filesDir, name)
	http.ServeFile(w, r, fullPath)
}

func (s *RelayServer) checkAdminAuth(w http.ResponseWriter, r *http.Request) bool {
	expected := s.adminToken
	if expected == "" {
		expected = s.authToken
	}
	if expected == "" {
		writeAPIError(w, http.StatusForbidden, "admin_disabled", "Configure --admin-token or --token to publish updates")
		return false
	}
	got := extractBearerToken(r)
	if subtle.ConstantTimeCompare([]byte(got), []byte(expected)) != 1 {
		writeAPIError(w, http.StatusUnauthorized, "unauthorized", "Invalid admin token")
		return false
	}
	return true
}

func (s *RelayServer) handleAdminUpdates(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdminAuth(w, r) {
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.updates.mu.RLock()
		m := s.updates.manifest
		s.updates.mu.RUnlock()
		writeJSON(w, http.StatusOK, m)

	case http.MethodPut, http.MethodPost:
		var entry ReleaseEntry
		if err := json.NewDecoder(io.LimitReader(r.Body, maxAuthBodyBytes)).Decode(&entry); err != nil {
			writeAPIError(w, http.StatusBadRequest, "invalid_json", "Invalid release JSON")
			return
		}
		if entry.Platform == "" || entry.LatestVersion == "" {
			writeAPIError(w, http.StatusBadRequest, "invalid_release", "platform and latestVersion are required")
			return
		}
		if err := s.updates.UpsertRelease(entry); err != nil {
			writeAPIError(w, http.StatusInternalServerError, "persist_failed", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "release": entry})

	default:
		writeAPIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "GET or PUT required")
	}
}
