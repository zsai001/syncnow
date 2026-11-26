package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	DefaultTmpChunkPlainBytes = 8 * 1024 * 1024 // 8 MiB plaintext -> 8,388,624 B ciphertext (satisfies R2 >= 5 MiB equal part rule)
	TmpChunkAEADTagBytes      = 16
	MaxTmpChunksPerTransfer   = 2048
	MinDiskFreeReserveBytes   = 128 * 1024 * 1024 // Keep at least 128 MiB free on Docker/VPS disk
)

type TmpTransferPart struct {
	PartNumber int    `json:"partNumber"`
	ETag       string `json:"etag"`
}

type TmpTransferMeta struct {
	TransferID       string          `json:"transferID"`
	GroupHash        string          `json:"groupHash"`
	SenderDeviceID   string          `json:"senderDeviceID"`
	StorageBackend   string          `json:"storageBackend"` // "disk" | "r2" | "do_sqlite"
	TotalPlainBytes  int64           `json:"totalPlainBytes"`
	TotalCipherBytes int64           `json:"totalCipherBytes"`
	ChunkPlainBytes  int             `json:"chunkPlainBytes"`
	ChunkCipherBytes int             `json:"chunkCipherBytes"`
	TotalChunks      int             `json:"totalChunks"`
	UploadedChunks   map[int]string  `json:"uploadedChunks"` // partIdx -> etag
	Status           string          `json:"status"`         // "uploading" | "ready"
	CreatedAtMs      int64           `json:"createdAtMs"`
	ExpiresAtMs      int64           `json:"expiresAtMs"`
	AckedDevices     map[string]bool `json:"ackedDevices"`
}

type TmpStatsSummary struct {
	StorageBackend     string         `json:"storageBackend"`
	ActiveFiles        int            `json:"activeFiles"`
	UploadingFiles     int            `json:"uploadingFiles"`
	UsedBytes          int64          `json:"usedBytes"`
	MaxTmpFileMB       int64          `json:"maxTmpFileMB"`
	MaxTmpTotalMB      int64          `json:"maxTmpTotalMB"`
	TmpTTLHours        int            `json:"tmpTTLHours"`
	TmpAckGraceMinutes int            `json:"tmpAckGraceMinutes"`
	DiskUsage          *DiskUsageInfo `json:"diskUsage,omitempty"`
}

type tmpTicketClaims struct {
	TransferID  string `json:"tid"`
	GroupHash   string `json:"grp"`
	ExpiresAtMs int64  `json:"exp"`
}

type TmpBlobStore struct {
	rootDir    string
	indexPath  string
	hmacSecret []byte

	mu        sync.RWMutex
	transfers map[string]*TmpTransferMeta
}

func NewTmpBlobStore(dataDir string) *TmpBlobStore {
	root := filepath.Join(dataDir, "tmp_blobs")
	_ = os.MkdirAll(root, 0o700)

	secretPath := filepath.Join(dataDir, "tmp_ticket.key")
	secret, err := os.ReadFile(secretPath)
	if err != nil || len(secret) < 32 {
		secret = make([]byte, 32)
		_, _ = rand.Read(secret)
		_ = os.WriteFile(secretPath, secret, 0o600)
	}

	st := &TmpBlobStore{
		rootDir:    root,
		indexPath:  filepath.Join(root, "index.json"),
		hmacSecret: secret,
		transfers:  make(map[string]*TmpTransferMeta),
	}
	st.load()
	return st
}

func (t *TmpBlobStore) load() {
	raw, err := os.ReadFile(t.indexPath)
	if err != nil {
		return
	}
	var list []*TmpTransferMeta
	if json.Unmarshal(raw, &list) == nil {
		for _, m := range list {
			if m == nil || m.TransferID == "" {
				continue
			}
			if m.UploadedChunks == nil {
				m.UploadedChunks = make(map[int]string)
			}
			if m.AckedDevices == nil {
				m.AckedDevices = make(map[string]bool)
			}
			t.transfers[m.TransferID] = m
		}
	}
}

func (t *TmpBlobStore) saveLocked() {
	list := make([]*TmpTransferMeta, 0, len(t.transfers))
	for _, m := range t.transfers {
		list = append(list, m)
	}
	raw, err := json.Marshal(list)
	if err != nil {
		return
	}
	tmp := t.indexPath + ".tmp"
	if os.WriteFile(tmp, raw, 0o600) == nil {
		_ = os.Rename(tmp, t.indexPath)
	}
}

func (t *TmpBlobStore) dataFilePath(groupHash, transferID string, part bool) string {
	name := transferID + ".bin"
	if part {
		name = transferID + ".part"
	}
	return filepath.Join(t.rootDir, groupHash, name)
}

func (t *TmpBlobStore) signTicket(transferID, groupHash string, expMs int64) string {
	claims := tmpTicketClaims{
		TransferID:  transferID,
		GroupHash:   groupHash,
		ExpiresAtMs: expMs,
	}
	raw, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(raw)
	mac := hmac.New(sha256.New, t.hmacSecret)
	mac.Write([]byte(payload))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return "v1." + payload + "." + sig
}

func (t *TmpBlobStore) verifyTicket(ticket, expectedTransferID, expectedGroupHash string) bool {
	parts := strings.Split(strings.TrimSpace(ticket), ".")
	if len(parts) != 3 || parts[0] != "v1" {
		return false
	}
	mac := hmac.New(sha256.New, t.hmacSecret)
	mac.Write([]byte(parts[1]))
	wantSig := mac.Sum(nil)
	gotSig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !hmac.Equal(gotSig, wantSig) {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	var claims tmpTicketClaims
	if json.Unmarshal(raw, &claims) != nil {
		return false
	}
	if claims.TransferID != expectedTransferID {
		return false
	}
	if expectedGroupHash != "" && claims.GroupHash != expectedGroupHash {
		return false
	}
	return time.Now().UnixMilli() < claims.ExpiresAtMs
}

func (t *TmpBlobStore) removeFilesForLocked(m *TmpTransferMeta) {
	_ = os.Remove(t.dataFilePath(m.GroupHash, m.TransferID, true))
	_ = os.Remove(t.dataFilePath(m.GroupHash, m.TransferID, false))
}

func (t *TmpBlobStore) usedBytesLocked() int64 {
	var sum int64
	for _, m := range t.transfers {
		sum += m.TotalCipherBytes
	}
	return sum
}

// evictForSpaceLocked cleans expired transfers first, then evicts acked transfers (oldest first),
// and finally oldest transfers until usedBytes + neededBytes <= maxTotalBytes.
func (t *TmpBlobStore) evictForSpaceLocked(neededBytes, maxTotalBytes int64, nowMs int64) {
	// 1. Expired or stale (>1h) incomplete uploads
	staleUploadCutoff := nowMs - 60*60*1000
	for id, m := range t.transfers {
		if nowMs >= m.ExpiresAtMs || (m.Status == "uploading" && m.CreatedAtMs < staleUploadCutoff) {
			t.removeFilesForLocked(m)
			delete(t.transfers, id)
		}
	}
	if t.usedBytesLocked()+neededBytes <= maxTotalBytes {
		return
	}

	// 2. Sort candidates: acked ready files first, then oldest expiry
	candidates := make([]*TmpTransferMeta, 0, len(t.transfers))
	for _, m := range t.transfers {
		if m.Status == "ready" {
			candidates = append(candidates, m)
		}
	}
	sort.Slice(candidates, func(i, j int) bool {
		ackI := len(candidates[i].AckedDevices) > 0
		ackJ := len(candidates[j].AckedDevices) > 0
		if ackI != ackJ {
			return ackI
		}
		return candidates[i].ExpiresAtMs < candidates[j].ExpiresAtMs
	})

	for _, cand := range candidates {
		if t.usedBytesLocked()+neededBytes <= maxTotalBytes {
			break
		}
		t.removeFilesForLocked(cand)
		delete(t.transfers, cand.TransferID)
	}
}

func (t *TmpBlobStore) CleanupExpired() {
	now := time.Now().UnixMilli()
	staleUploadCutoff := now - 60*60*1000
	t.mu.Lock()
	changed := false
	for id, m := range t.transfers {
		if now >= m.ExpiresAtMs || (m.Status == "uploading" && m.CreatedAtMs < staleUploadCutoff) {
			t.removeFilesForLocked(m)
			delete(t.transfers, id)
			changed = true
		}
	}
	if changed {
		t.saveLocked()
	}
	t.mu.Unlock()
}

func (t *TmpBlobStore) PurgeAll() (int, int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	count := len(t.transfers)
	var freed int64
	for id, m := range t.transfers {
		freed += m.TotalCipherBytes
		t.removeFilesForLocked(m)
		delete(t.transfers, id)
	}
	_ = os.RemoveAll(t.rootDir)
	_ = os.MkdirAll(t.rootDir, 0o700)
	t.saveLocked()
	return count, freed
}

func (t *TmpBlobStore) Stats(cfg DynamicRelayConfig) TmpStatsSummary {
	t.CleanupExpired()
	t.mu.RLock()
	var active, uploading int
	var used int64
	for _, m := range t.transfers {
		used += m.TotalCipherBytes
		if m.Status == "ready" {
			active++
		} else {
			uploading++
		}
	}
	t.mu.RUnlock()

	return TmpStatsSummary{
		StorageBackend:     "disk",
		ActiveFiles:        active,
		UploadingFiles:     uploading,
		UsedBytes:          used,
		MaxTmpFileMB:       cfg.MaxTmpFileMB,
		MaxTmpTotalMB:      cfg.MaxTmpTotalMB,
		TmpTTLHours:        cfg.TmpTTLHours,
		TmpAckGraceMinutes: cfg.TmpAckGraceMinutes,
		DiskUsage:          queryDiskUsage(t.rootDir),
	}
}

func expectedPartCipherLen(m *TmpTransferMeta, partIdx int) int64 {
	if partIdx < 0 || partIdx >= m.TotalChunks {
		return -1
	}
	if partIdx < m.TotalChunks-1 {
		return int64(m.ChunkCipherBytes)
	}
	prevBytes := int64(m.TotalChunks-1) * int64(m.ChunkCipherBytes)
	return m.TotalCipherBytes - prevBytes
}

// MARK: - HTTP Handlers on RelayServer (`/v1/tmp/*`)

func (s *RelayServer) checkTmpAuthOrTicket(w http.ResponseWriter, r *http.Request, transferID, groupHash string) bool {
	if ticket := strings.TrimSpace(r.Header.Get("X-SyncNow-Ticket")); ticket != "" {
		if s.tmpBlobs.verifyTicket(ticket, transferID, groupHash) {
			return true
		}
	}
	if qTicket := strings.TrimSpace(r.URL.Query().Get("ticket")); qTicket != "" {
		if s.tmpBlobs.verifyTicket(qTicket, transferID, groupHash) {
			return true
		}
	}
	return s.checkAuth(w, r)
}

func (s *RelayServer) handleTmpRoutes(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if path == "/v1/tmp/init" {
		s.handleTmpInit(w, r)
		return
	}

	rest := strings.TrimPrefix(path, "/v1/tmp/")
	segments := strings.Split(rest, "/")
	if len(segments) == 0 || !safeIDRegex.MatchString(segments[0]) {
		writeAPIError(w, http.StatusBadRequest, "invalid_transfer_id", "valid transferID is required")
		return
	}
	transferID := segments[0]

	if len(segments) == 1 {
		switch r.Method {
		case http.MethodGet:
			s.handleTmpStreamDownload(w, r, transferID)
		case http.MethodDelete:
			s.handleTmpDelete(w, r, transferID)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
		return
	}

	if len(segments) == 2 && segments[1] == "complete" && r.Method == http.MethodPost {
		s.handleTmpComplete(w, r, transferID)
		return
	}

	if len(segments) == 2 && segments[1] == "ack" && r.Method == http.MethodPost {
		s.handleTmpAck(w, r, transferID)
		return
	}

	if len(segments) == 3 && segments[1] == "parts" {
		partIdx, err := strconv.Atoi(segments[2])
		if err != nil || partIdx < 0 || partIdx >= MaxTmpChunksPerTransfer {
			writeAPIError(w, http.StatusBadRequest, "invalid_part", "invalid part index")
			return
		}
		switch r.Method {
		case http.MethodPut, http.MethodPost:
			s.handleTmpUploadPart(w, r, transferID, partIdx)
		case http.MethodGet:
			s.handleTmpDownloadPart(w, r, transferID, partIdx)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
		return
	}

	http.NotFound(w, r)
}

func (s *RelayServer) handleTmpInit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.checkAuth(w, r) {
		return
	}

	var req struct {
		TransferID       string `json:"transferID"`
		GroupHash        string `json:"groupHash"`
		SenderDeviceID   string `json:"senderDeviceID"`
		TotalPlainBytes  int64  `json:"totalPlainBytes"`
		TotalCipherBytes int64  `json:"totalCipherBytes"`
		ChunkPlainBytes  int    `json:"chunkPlainBytes"`
		TotalChunks      int    `json:"totalChunks"`
		TTLHours         int    `json:"ttlHours"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 64*1024)).Decode(&req); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_json", "invalid json payload")
		return
	}
	if !safeIDRegex.MatchString(req.TransferID) || !safeIDRegex.MatchString(req.GroupHash) {
		writeAPIError(w, http.StatusBadRequest, "invalid_params", "valid transferID and groupHash are required")
		return
	}
	if req.ChunkPlainBytes <= 0 {
		req.ChunkPlainBytes = DefaultTmpChunkPlainBytes
	}
	if req.ChunkPlainBytes < 64*1024 || req.ChunkPlainBytes > 32*1024*1024 {
		writeAPIError(w, http.StatusBadRequest, "invalid_chunk_size", "chunkPlainBytes must be between 64KB and 32MB")
		return
	}
	expectedChunks := int((req.TotalPlainBytes + int64(req.ChunkPlainBytes) - 1) / int64(req.ChunkPlainBytes))
	if req.TotalPlainBytes <= 0 || req.TotalChunks <= 0 || req.TotalChunks != expectedChunks || req.TotalChunks > MaxTmpChunksPerTransfer {
		writeAPIError(w, http.StatusBadRequest, "invalid_chunks", "invalid totalPlainBytes or totalChunks")
		return
	}
	expectedCipher := req.TotalPlainBytes + int64(req.TotalChunks)*TmpChunkAEADTagBytes
	if req.TotalCipherBytes != expectedCipher {
		writeAPIError(w, http.StatusBadRequest, "invalid_cipher_size", "totalCipherBytes mismatch")
		return
	}

	cfg := s.currentConfig()
	maxFileBytes := cfg.MaxTmpFileMB * 1024 * 1024
	if req.TotalCipherBytes > maxFileBytes {
		writeAPIError(w, http.StatusRequestEntityTooLarge, "file_too_large", fmt.Sprintf("file exceeds maxTmpFileMB (%d MB)", cfg.MaxTmpFileMB))
		return
	}

	ttlHours := cfg.TmpTTLHours
	if req.TTLHours > 0 && req.TTLHours < ttlHours {
		ttlHours = req.TTLHours
	}
	now := time.Now().UnixMilli()
	expMs := now + int64(ttlHours)*60*60*1000

	s.tmpBlobs.mu.Lock()
	if existing := s.tmpBlobs.transfers[req.TransferID]; existing != nil && existing.GroupHash == req.GroupHash && now < existing.ExpiresAtMs {
		uploaded := make([]int, 0, len(existing.UploadedChunks))
		for idx := range existing.UploadedChunks {
			uploaded = append(uploaded, idx)
		}
		sort.Ints(uploaded)
		ticket := s.tmpBlobs.signTicket(existing.TransferID, existing.GroupHash, existing.ExpiresAtMs)
		s.tmpBlobs.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{
			"transferID":       existing.TransferID,
			"storageBackend":   "disk",
			"chunkPlainBytes":  existing.ChunkPlainBytes,
			"chunkCipherBytes": existing.ChunkCipherBytes,
			"totalChunks":      existing.TotalChunks,
			"expiresAtMs":      existing.ExpiresAtMs,
			"ticket":           ticket,
			"uploadedChunks":   uploaded,
			"status":           existing.Status,
		})
		return
	}

	maxTotalBytes := cfg.MaxTmpTotalMB * 1024 * 1024
	s.tmpBlobs.evictForSpaceLocked(req.TotalCipherBytes, maxTotalBytes, now)
	if s.tmpBlobs.usedBytesLocked()+req.TotalCipherBytes > maxTotalBytes {
		s.tmpBlobs.mu.Unlock()
		writeAPIError(w, http.StatusInsufficientStorage, "quota_exceeded", fmt.Sprintf("relay tmp storage full (limit %d MB)", cfg.MaxTmpTotalMB))
		return
	}

	// Docker / Linux VPS real OS disk free-space guard
	if du := queryDiskUsage(s.tmpBlobs.rootDir); du != nil && du.FreeBytes > 0 {
		if int64(du.FreeBytes)-req.TotalCipherBytes < MinDiskFreeReserveBytes {
			s.tmpBlobs.mu.Unlock()
			writeAPIError(w, http.StatusInsufficientStorage, "disk_full", "insufficient free disk space on relay server")
			return
		}
	}

	groupDir := filepath.Join(s.tmpBlobs.rootDir, req.GroupHash)
	if err := os.MkdirAll(groupDir, 0o700); err != nil {
		s.tmpBlobs.mu.Unlock()
		writeAPIError(w, http.StatusInternalServerError, "storage_error", err.Error())
		return
	}
	partPath := s.tmpBlobs.dataFilePath(req.GroupHash, req.TransferID, true)
	f, err := os.OpenFile(partPath, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o600)
	if err != nil {
		s.tmpBlobs.mu.Unlock()
		writeAPIError(w, http.StatusInternalServerError, "storage_error", err.Error())
		return
	}
	_ = f.Close()

	meta := &TmpTransferMeta{
		TransferID:       req.TransferID,
		GroupHash:        req.GroupHash,
		SenderDeviceID:   req.SenderDeviceID,
		StorageBackend:   "disk",
		TotalPlainBytes:  req.TotalPlainBytes,
		TotalCipherBytes: req.TotalCipherBytes,
		ChunkPlainBytes:  req.ChunkPlainBytes,
		ChunkCipherBytes: req.ChunkPlainBytes + TmpChunkAEADTagBytes,
		TotalChunks:      req.TotalChunks,
		UploadedChunks:   make(map[int]string),
		Status:           "uploading",
		CreatedAtMs:      now,
		ExpiresAtMs:      expMs,
		AckedDevices:     make(map[string]bool),
	}
	s.tmpBlobs.transfers[req.TransferID] = meta
	s.tmpBlobs.saveLocked()
	ticket := s.tmpBlobs.signTicket(meta.TransferID, meta.GroupHash, meta.ExpiresAtMs)
	s.tmpBlobs.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"transferID":       meta.TransferID,
		"storageBackend":   "disk",
		"chunkPlainBytes":  meta.ChunkPlainBytes,
		"chunkCipherBytes": meta.ChunkCipherBytes,
		"totalChunks":      meta.TotalChunks,
		"expiresAtMs":      meta.ExpiresAtMs,
		"ticket":           ticket,
		"uploadedChunks":   []int{},
		"status":           meta.Status,
	})
}

func (s *RelayServer) handleTmpUploadPart(w http.ResponseWriter, r *http.Request, transferID string, partIdx int) {
	groupHash := strings.TrimSpace(r.URL.Query().Get("group"))
	if !s.checkTmpAuthOrTicket(w, r, transferID, groupHash) {
		return
	}

	s.tmpBlobs.mu.RLock()
	meta := s.tmpBlobs.transfers[transferID]
	if meta == nil || (groupHash != "" && meta.GroupHash != groupHash) {
		s.tmpBlobs.mu.RUnlock()
		writeAPIError(w, http.StatusNotFound, "not_found", "transfer not found")
		return
	}
	if meta.Status != "uploading" {
		s.tmpBlobs.mu.RUnlock()
		writeAPIError(w, http.StatusConflict, "already_completed", "transfer already finalized")
		return
	}
	wantLen := expectedPartCipherLen(meta, partIdx)
	chunkStride := int64(meta.ChunkCipherBytes)
	mGroup := meta.GroupHash
	s.tmpBlobs.mu.RUnlock()

	if wantLen <= 0 {
		writeAPIError(w, http.StatusBadRequest, "invalid_part", "part index out of range")
		return
	}

	partPath := s.tmpBlobs.dataFilePath(mGroup, transferID, true)
	f, err := os.OpenFile(partPath, os.O_WRONLY, 0o600)
	if err != nil {
		writeAPIError(w, http.StatusNotFound, "not_found", "staging file missing")
		return
	}
	defer f.Close()

	baseOffset := int64(partIdx) * chunkStride
	limited := io.LimitReader(r.Body, wantLen+1)
	buf := make([]byte, 256*1024)
	var written int64
	hasher := sha256.New()

	for {
		n, readErr := limited.Read(buf)
		if n > 0 {
			if written+int64(n) > wantLen {
				writeAPIError(w, http.StatusRequestEntityTooLarge, "part_too_large", "chunk exceeds expected cipher size")
				return
			}
			if _, wErr := f.WriteAt(buf[:n], baseOffset+written); wErr != nil {
				writeAPIError(w, http.StatusInternalServerError, "write_error", wErr.Error())
				return
			}
			hasher.Write(buf[:n])
			written += int64(n)
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			writeAPIError(w, http.StatusBadRequest, "read_error", readErr.Error())
			return
		}
	}

	if written != wantLen {
		writeAPIError(w, http.StatusBadRequest, "part_size_mismatch", fmt.Sprintf("expected %d bytes, got %d", wantLen, written))
		return
	}

	etag := hex.EncodeToString(hasher.Sum(nil)[:12])
	s.tmpBlobs.mu.Lock()
	if cur := s.tmpBlobs.transfers[transferID]; cur != nil && cur.Status == "uploading" {
		cur.UploadedChunks[partIdx] = etag
		s.tmpBlobs.saveLocked()
	}
	s.tmpBlobs.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"partIndex":  partIdx,
		"partNumber": partIdx + 1,
		"etag":       etag,
	})
}

func (s *RelayServer) handleTmpComplete(w http.ResponseWriter, r *http.Request, transferID string) {
	if !s.checkAuth(w, r) {
		return
	}
	var req struct {
		GroupHash string            `json:"groupHash"`
		Parts     []TmpTransferPart `json:"parts"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 256*1024)).Decode(&req)

	s.tmpBlobs.mu.Lock()
	meta := s.tmpBlobs.transfers[transferID]
	if meta == nil || (req.GroupHash != "" && meta.GroupHash != req.GroupHash) {
		s.tmpBlobs.mu.Unlock()
		writeAPIError(w, http.StatusNotFound, "not_found", "transfer not found")
		return
	}
	if meta.Status == "ready" {
		ticket := s.tmpBlobs.signTicket(meta.TransferID, meta.GroupHash, meta.ExpiresAtMs)
		exp := meta.ExpiresAtMs
		s.tmpBlobs.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":          true,
			"transferID":  transferID,
			"expiresAtMs": exp,
			"ticket":      ticket,
		})
		return
	}
	if len(meta.UploadedChunks) < meta.TotalChunks {
		missing := meta.TotalChunks - len(meta.UploadedChunks)
		s.tmpBlobs.mu.Unlock()
		writeAPIError(w, http.StatusBadRequest, "incomplete_parts", fmt.Sprintf("missing %d chunk(s)", missing))
		return
	}

	partPath := s.tmpBlobs.dataFilePath(meta.GroupHash, transferID, true)
	finalPath := s.tmpBlobs.dataFilePath(meta.GroupHash, transferID, false)
	if err := os.Rename(partPath, finalPath); err != nil {
		s.tmpBlobs.mu.Unlock()
		writeAPIError(w, http.StatusInternalServerError, "finalize_failed", err.Error())
		return
	}
	meta.Status = "ready"
	s.tmpBlobs.saveLocked()
	ticket := s.tmpBlobs.signTicket(meta.TransferID, meta.GroupHash, meta.ExpiresAtMs)
	exp := meta.ExpiresAtMs
	s.tmpBlobs.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":          true,
		"transferID":  transferID,
		"expiresAtMs": exp,
		"ticket":      ticket,
	})
}

func (s *RelayServer) handleTmpDownloadPart(w http.ResponseWriter, r *http.Request, transferID string, partIdx int) {
	groupHash := strings.TrimSpace(r.URL.Query().Get("group"))
	if !s.checkTmpAuthOrTicket(w, r, transferID, groupHash) {
		return
	}

	now := time.Now().UnixMilli()
	s.tmpBlobs.mu.RLock()
	meta := s.tmpBlobs.transfers[transferID]
	if meta == nil || meta.Status != "ready" || now >= meta.ExpiresAtMs || (groupHash != "" && meta.GroupHash != groupHash) {
		s.tmpBlobs.mu.RUnlock()
		writeAPIError(w, http.StatusNotFound, "not_found", "tmp blob not found or expired")
		return
	}
	partLen := expectedPartCipherLen(meta, partIdx)
	offset := int64(partIdx) * int64(meta.ChunkCipherBytes)
	finalPath := s.tmpBlobs.dataFilePath(meta.GroupHash, transferID, false)
	s.tmpBlobs.mu.RUnlock()

	if partLen <= 0 {
		writeAPIError(w, http.StatusBadRequest, "invalid_part", "part index out of range")
		return
	}

	f, err := os.Open(finalPath)
	if err != nil {
		writeAPIError(w, http.StatusNotFound, "not_found", "tmp file missing")
		return
	}
	defer f.Close()

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(partLen, 10))
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, io.NewSectionReader(f, offset, partLen))
}

func (s *RelayServer) handleTmpStreamDownload(w http.ResponseWriter, r *http.Request, transferID string) {
	groupHash := strings.TrimSpace(r.URL.Query().Get("group"))
	if !s.checkTmpAuthOrTicket(w, r, transferID, groupHash) {
		return
	}

	now := time.Now().UnixMilli()
	s.tmpBlobs.mu.RLock()
	meta := s.tmpBlobs.transfers[transferID]
	if meta == nil || meta.Status != "ready" || now >= meta.ExpiresAtMs || (groupHash != "" && meta.GroupHash != groupHash) {
		s.tmpBlobs.mu.RUnlock()
		writeAPIError(w, http.StatusNotFound, "not_found", "tmp blob not found or expired")
		return
	}
	finalPath := s.tmpBlobs.dataFilePath(meta.GroupHash, transferID, false)
	modTime := time.UnixMilli(meta.CreatedAtMs)
	s.tmpBlobs.mu.RUnlock()

	f, err := os.Open(finalPath)
	if err != nil {
		writeAPIError(w, http.StatusNotFound, "not_found", "tmp file missing")
		return
	}
	defer f.Close()

	w.Header().Set("Content-Type", "application/octet-stream")
	// http.ServeContent natively supports HTTP Range / 206 Partial Content with zero heap buffering!
	http.ServeContent(w, r, transferID+".bin", modTime, f)
}

func (s *RelayServer) handleTmpAck(w http.ResponseWriter, r *http.Request, transferID string) {
	if !s.checkAuth(w, r) {
		return
	}
	var req struct {
		GroupHash string `json:"groupHash"`
		DeviceID  string `json:"deviceID"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 16*1024)).Decode(&req)

	cfg := s.currentConfig()
	graceMin := cfg.TmpAckGraceMinutes
	now := time.Now().UnixMilli()

	s.tmpBlobs.mu.Lock()
	meta := s.tmpBlobs.transfers[transferID]
	if meta == nil || (req.GroupHash != "" && meta.GroupHash != req.GroupHash) {
		s.tmpBlobs.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "deleted": true})
		return
	}
	if req.DeviceID != "" {
		meta.AckedDevices[req.DeviceID] = true
	}

	deleted := false
	if graceMin == 0 {
		s.tmpBlobs.removeFilesForLocked(meta)
		delete(s.tmpBlobs.transfers, transferID)
		deleted = true
	} else if graceMin > 0 {
		graceExp := now + int64(graceMin)*60*1000
		if graceExp < meta.ExpiresAtMs {
			meta.ExpiresAtMs = graceExp
		}
	}
	s.tmpBlobs.saveLocked()
	exp := meta.ExpiresAtMs
	s.tmpBlobs.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":          true,
		"deleted":     deleted,
		"expiresAtMs": exp,
	})
}

func (s *RelayServer) handleTmpDelete(w http.ResponseWriter, r *http.Request, transferID string) {
	if !s.checkAuth(w, r) {
		return
	}
	groupHash := strings.TrimSpace(r.URL.Query().Get("group"))
	s.tmpBlobs.mu.Lock()
	meta := s.tmpBlobs.transfers[transferID]
	deleted := false
	if meta != nil && (groupHash == "" || meta.GroupHash == groupHash) {
		s.tmpBlobs.removeFilesForLocked(meta)
		delete(s.tmpBlobs.transfers, transferID)
		s.tmpBlobs.saveLocked()
		deleted = true
	}
	s.tmpBlobs.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "deleted": deleted})
}
