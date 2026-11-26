package main

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// KnownAccountDevice stores public identity & X25519 key-wrapping metadata for same-account devices
// so peers can wrap the E2EE `SNK-` group key asynchronously even when never online simultaneously.
type KnownAccountDevice struct {
	DeviceID               string          `json:"deviceID"`
	DeviceName             string          `json:"deviceName"`
	Platform               string          `json:"platform"`
	SigningPublicKeyBase64 string          `json:"signingPublicKeyBase64"`
	X25519PublicKeyBase64  string          `json:"x25519PublicKeyBase64,omitempty"`
	X25519SignatureBase64  string          `json:"x25519SignatureBase64,omitempty"`
	AccountCert            json.RawMessage `json:"accountCert,omitempty"`
	UpdatedAtMs            int64           `json:"updatedAtMs"`
}

// SealedGroupKeyEnvelope carries an X25519+ChaCha20-Poly1305 wrapped `SNK-` group key targeted at one device.
// The relay server never sees the plaintext group key.
type SealedGroupKeyEnvelope struct {
	TargetDeviceID              string          `json:"targetDeviceID"`
	SenderDeviceID              string          `json:"senderDeviceID"`
	SenderSigningPublicKeyBase64 string         `json:"senderSigningPublicKeyBase64"`
	SenderAccountCert           json.RawMessage `json:"senderAccountCert,omitempty"`
	EphemeralX25519PubBase64    string          `json:"ephemeralX25519PubBase64"`
	CiphertextBase64            string          `json:"ciphertextBase64"`
	GroupHash                   string          `json:"groupHash"`
	KeyUpdatedAtMs              int64           `json:"keyUpdatedAtMs"`
	SignatureBase64             string          `json:"signatureBase64"`
	CreatedAtMs                 int64           `json:"createdAtMs"`
}

type persistedRoomVault struct {
	Devices   map[string]KnownAccountDevice     `json:"devices"`
	Envelopes map[string]SealedGroupKeyEnvelope `json:"envelopes"` // targetDeviceID -> latest sealed envelope
}

type GroupKeyVaultStore struct {
	roomsDir string
	mu       sync.RWMutex
	rooms    map[string]*persistedRoomVault
}

func NewGroupKeyVaultStore(dataDir string) *GroupKeyVaultStore {
	dir := filepath.Join(dataDir, "signal_vaults")
	_ = os.MkdirAll(dir, 0o700)
	s := &GroupKeyVaultStore{
		roomsDir: dir,
		rooms:    make(map[string]*persistedRoomVault),
	}
	s.loadAll()
	return s
}

func (g *GroupKeyVaultStore) loadAll() {
	entries, err := os.ReadDir(g.roomsDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		roomID := strings.TrimSuffix(e.Name(), ".json")
		if !safeIDRegex.MatchString(roomID) {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(g.roomsDir, e.Name()))
		if err != nil {
			continue
		}
		var v persistedRoomVault
		if json.Unmarshal(raw, &v) == nil {
			if v.Devices == nil {
				v.Devices = make(map[string]KnownAccountDevice)
			}
			if v.Envelopes == nil {
				v.Envelopes = make(map[string]SealedGroupKeyEnvelope)
			}
			g.rooms[roomID] = &v
		}
	}
}

func (g *GroupKeyVaultStore) ensureRoomLocked(roomID string) *persistedRoomVault {
	r := g.rooms[roomID]
	if r == nil {
		r = &persistedRoomVault{
			Devices:   make(map[string]KnownAccountDevice),
			Envelopes: make(map[string]SealedGroupKeyEnvelope),
		}
		g.rooms[roomID] = r
	}
	return r
}

func (g *GroupKeyVaultStore) saveRoomLocked(roomID string, r *persistedRoomVault) {
	if !safeIDRegex.MatchString(roomID) {
		return
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return
	}
	path := filepath.Join(g.roomsDir, roomID+".json")
	tmp := path + ".tmp"
	if os.WriteFile(tmp, raw, 0o600) == nil {
		_ = os.Rename(tmp, path)
	}
}

func (g *GroupKeyVaultStore) UpsertDevice(roomID string, dev KnownAccountDevice) {
	if !safeIDRegex.MatchString(roomID) || !safeIDRegex.MatchString(dev.DeviceID) || dev.SigningPublicKeyBase64 == "" {
		return
	}
	dev.UpdatedAtMs = time.Now().UnixMilli()
	g.mu.Lock()
	r := g.ensureRoomLocked(roomID)
	if existing, ok := r.Devices[dev.DeviceID]; ok {
		if dev.X25519PublicKeyBase64 == "" {
			dev.X25519PublicKeyBase64 = existing.X25519PublicKeyBase64
			dev.X25519SignatureBase64 = existing.X25519SignatureBase64
		}
		if len(dev.AccountCert) == 0 {
			dev.AccountCert = existing.AccountCert
		}
	}
	r.Devices[dev.DeviceID] = dev

	// Bound max stored devices per room to 32 (evict oldest UpdatedAtMs)
	if len(r.Devices) > 32 {
		type pair struct {
			id string
			ts int64
		}
		var list []pair
		for id, d := range r.Devices {
			list = append(list, pair{id, d.UpdatedAtMs})
		}
		sort.Slice(list, func(i, j int) bool { return list[i].ts < list[j].ts })
		for i := 0; i < len(list)-32; i++ {
			delete(r.Devices, list[i].id)
			delete(r.Envelopes, list[i].id)
		}
	}
	g.saveRoomLocked(roomID, r)
	g.mu.Unlock()
}

func (g *GroupKeyVaultStore) GetForDevice(roomID, deviceID string) ([]KnownAccountDevice, *SealedGroupKeyEnvelope) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	r := g.rooms[roomID]
	if r == nil {
		return []KnownAccountDevice{}, nil
	}
	devs := make([]KnownAccountDevice, 0, len(r.Devices))
	for _, d := range r.Devices {
		devs = append(devs, d)
	}
	sort.Slice(devs, func(i, j int) bool { return devs[i].DeviceID < devs[j].DeviceID })
	var env *SealedGroupKeyEnvelope
	if e, ok := r.Envelopes[deviceID]; ok {
		cp := e
		env = &cp
	}
	return devs, env
}

func (g *GroupKeyVaultStore) StoreEnvelopes(roomID, senderDeviceID string, envelopes []SealedGroupKeyEnvelope) []string {
	if !safeIDRegex.MatchString(roomID) || len(envelopes) == 0 {
		return nil
	}
	now := time.Now().UnixMilli()
	var updatedTargets []string

	g.mu.Lock()
	r := g.ensureRoomLocked(roomID)
	for _, env := range envelopes {
		if !safeIDRegex.MatchString(env.TargetDeviceID) || env.CiphertextBase64 == "" || env.EphemeralX25519PubBase64 == "" {
			continue
		}
		env.SenderDeviceID = senderDeviceID
		env.CreatedAtMs = now
		if prev, ok := r.Envelopes[env.TargetDeviceID]; ok && prev.KeyUpdatedAtMs > env.KeyUpdatedAtMs {
			continue
		}
		r.Envelopes[env.TargetDeviceID] = env
		updatedTargets = append(updatedTargets, env.TargetDeviceID)
	}
	if len(updatedTargets) > 0 {
		g.saveRoomLocked(roomID, r)
	}
	g.mu.Unlock()
	return updatedTargets
}

func (s *RelayServer) handleSignalGroupVault(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.authenticateRequest(w, r)
	if !ok {
		return
	}

	switch r.Method {
	case http.MethodGet:
		deviceID := strings.TrimSpace(r.URL.Query().Get("device"))
		if !safeIDRegex.MatchString(deviceID) {
			writeAPIError(w, http.StatusBadRequest, "invalid_device", "valid device query parameter is required")
			return
		}
		devs, env := s.groupVault.GetForDevice(principal.RoomID, deviceID)
		writeJSON(w, http.StatusOK, map[string]any{
			"userID":        principal.RoomID,
			"devices":       devs,
			"envelopeForMe": env,
			"timeMs":        time.Now().UnixMilli(),
		})

	case http.MethodPut, http.MethodPost:
		var req struct {
			Device    *KnownAccountDevice      `json:"device,omitempty"`
			SenderID  string                   `json:"senderDeviceID"`
			Envelopes []SealedGroupKeyEnvelope `json:"envelopes"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 256*1024)).Decode(&req); err != nil {
			writeAPIError(w, http.StatusBadRequest, "invalid_json", "invalid json payload")
			return
		}
		if req.Device != nil && safeIDRegex.MatchString(req.Device.DeviceID) {
			s.groupVault.UpsertDevice(principal.RoomID, *req.Device)
		}
		senderID := strings.TrimSpace(req.SenderID)
		if senderID == "" && req.Device != nil {
			senderID = req.Device.DeviceID
		}
		var notified int
		if safeIDRegex.MatchString(senderID) && len(req.Envelopes) > 0 {
			targets := s.groupVault.StoreEnvelopes(principal.RoomID, senderID, req.Envelopes)
			for _, targetID := range targets {
				if peer := s.signaling.findPeer(principal.RoomID, targetID); peer != nil {
					msg, _ := json.Marshal(SignalServerMessage{
						Type:         "signal",
						UserID:       principal.RoomID,
						FromDeviceID: senderID,
						Kind:         "group_vault_updated",
						Payload:      "{}",
						TimeMs:       time.Now().UnixMilli(),
					})
					_ = peer.ws.WriteText(msg)
					notified++
				}
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":       true,
			"notified": notified,
		})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ============================================================================
// Zero-Knowledge WebSocket Binary PeerSession Tunnel (`/v1/tunnel/ws`)
// ============================================================================

type tunnelSlot struct {
	roomID   string
	tunnelID string
	dialID   string
	acceptID string
	dialWS   *wsConn
	acceptWS *wsConn
	pairedCh chan struct{}
	once     sync.Once
}

type TunnelHub struct {
	mu    sync.Mutex
	slots map[string]*tunnelSlot // key: roomID + "|" + tunnelID
}

func NewTunnelHub() *TunnelHub {
	return &TunnelHub{
		slots: make(map[string]*tunnelSlot),
	}
}

func (s *RelayServer) handleTunnelWS(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.authenticateRequest(w, r)
	if !ok {
		return
	}

	tunnelID := strings.TrimSpace(r.URL.Query().Get("tunnel"))
	deviceID := strings.TrimSpace(r.URL.Query().Get("device"))
	peerID := strings.TrimSpace(r.URL.Query().Get("peer"))
	role := strings.TrimSpace(r.URL.Query().Get("role"))

	if !safeIDRegex.MatchString(tunnelID) || !safeIDRegex.MatchString(deviceID) || !safeIDRegex.MatchString(peerID) || deviceID == peerID {
		writeAPIError(w, http.StatusBadRequest, "invalid_params", "valid tunnel, device, and peer query parameters are required")
		return
	}
	if role != "dial" && role != "accept" {
		writeAPIError(w, http.StatusBadRequest, "invalid_role", "role must be dial or accept")
		return
	}

	ws, err := upgradeWebSocket(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	slotKey := principal.RoomID + "|" + tunnelID

	s.tunnels.mu.Lock()
	slot := s.tunnels.slots[slotKey]
	if slot == nil {
		slot = &tunnelSlot{
			roomID:   principal.RoomID,
			tunnelID: tunnelID,
			pairedCh: make(chan struct{}),
		}
		s.tunnels.slots[slotKey] = slot
	}

	if role == "dial" {
		if slot.dialWS != nil {
			s.tunnels.mu.Unlock()
			_ = ws.Close()
			return
		}
		slot.dialID = deviceID
		slot.dialWS = ws
	} else {
		if slot.acceptWS != nil {
			s.tunnels.mu.Unlock()
			_ = ws.Close()
			return
		}
		slot.acceptID = deviceID
		slot.acceptWS = ws
	}

	bothReady := slot.dialWS != nil && slot.acceptWS != nil
	if bothReady {
		slot.once.Do(func() { close(slot.pairedCh) })
	}
	s.tunnels.mu.Unlock()

	cleanup := func() {
		s.tunnels.mu.Lock()
		cur := s.tunnels.slots[slotKey]
		var partner *wsConn
		if cur == slot {
			delete(s.tunnels.slots, slotKey)
			if role == "dial" {
				partner = slot.acceptWS
			} else {
				partner = slot.dialWS
			}
		}
		s.tunnels.mu.Unlock()
		_ = ws.Close()
		if partner != nil {
			_ = partner.Close()
		}
	}
	defer cleanup()

	// Wait up to 15s for the remote peer to attach to the tunnel slot
	select {
	case <-slot.pairedCh:
	case <-time.After(15 * time.Second):
		return
	}

	var partner *wsConn
	if role == "dial" {
		partner = slot.acceptWS
	} else {
		partner = slot.dialWS
	}
	if partner == nil {
		return
	}

	// Notify this side that the bidirectional byte stream is live so PeerSession starts its Hello handshake
	readyJSON := []byte(`{"type":"tunnel_ready"}`)
	if err := ws.WriteText(readyJSON); err != nil {
		return
	}

	// Pump opaque encrypted WireFrame binary chunks (and app-level ping/pong) until disconnect
	for {
		op, payload, err := ws.ReadMessage(16 * 1024 * 1024)
		if err != nil {
			return
		}
		switch op {
		case wsOpBinary:
			if err := partner.WriteBinary(payload); err != nil {
				return
			}
		case wsOpText:
			var ctrl struct {
				Type string `json:"type"`
			}
			if json.Unmarshal(payload, &ctrl) == nil && ctrl.Type == "ping" {
				pong, _ := json.Marshal(map[string]any{"type": "pong", "timeMs": time.Now().UnixMilli()})
				_ = ws.WriteText(pong)
			}
		}
	}
}
