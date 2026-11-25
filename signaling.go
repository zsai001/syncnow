package main

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type SignalEndpoint struct {
	Host    string `json:"host"`
	TCPPort uint16 `json:"tcpPort"`
	UDPPort uint16 `json:"udpPort"`
}

type SignalPeerPresence struct {
	DeviceID               string           `json:"deviceID"`
	DeviceName             string           `json:"deviceName"`
	Platform               string           `json:"platform"`
	SigningPublicKeyBase64 string           `json:"signingPublicKeyBase64"`
	AccountCert            json.RawMessage  `json:"accountCert,omitempty"`
	LANEndpoints           []SignalEndpoint `json:"lanEndpoints"`
	ObservedPublicIP       string           `json:"observedPublicIP,omitempty"`
	TCPPort                uint16           `json:"tcpPort"`
	UDPPort                uint16           `json:"udpPort"`
	AppVersion             string           `json:"appVersion"`
	Online                 bool             `json:"online"`
	UpdatedAtMs            int64            `json:"updatedAtMs"`
}

type SignalClientMessage struct {
	Type           string              `json:"type"`
	Presence       *SignalPeerPresence `json:"presence,omitempty"`
	TargetDeviceID string              `json:"targetDeviceID,omitempty"`
	Kind           string              `json:"kind,omitempty"`
	Payload        string              `json:"payload,omitempty"`
}

type SignalServerMessage struct {
	Type         string               `json:"type"`
	UserID       string               `json:"userID,omitempty"`
	Peers        []SignalPeerPresence `json:"peers,omitempty"`
	Peer         *SignalPeerPresence  `json:"peer,omitempty"`
	DeviceID     string               `json:"deviceID,omitempty"`
	FromDeviceID string               `json:"fromDeviceID,omitempty"`
	Kind         string               `json:"kind,omitempty"`
	Payload      string               `json:"payload,omitempty"`
	TimeMs       int64                `json:"timeMs,omitempty"`
}

type signalClient struct {
	userID   string
	deviceID string
	ws       *wsConn
	presence SignalPeerPresence
}

// SignalingHub isolates peer presence and direct-connect signaling strictly by verified xtags.top userID.
type SignalingHub struct {
	mu    sync.RWMutex
	rooms map[string]map[string]*signalClient
}

func NewSignalingHub() *SignalingHub {
	return &SignalingHub{
		rooms: make(map[string]map[string]*signalClient),
	}
}

func (h *SignalingHub) register(c *signalClient) []SignalPeerPresence {
	h.mu.Lock()
	defer h.mu.Unlock()
	room := h.rooms[c.userID]
	if room == nil {
		room = make(map[string]*signalClient)
		h.rooms[c.userID] = room
	}
	// Replace any stale connection for the exact same deviceID cleanly
	if old := room[c.deviceID]; old != nil && old != c {
		_ = old.ws.Close()
	}
	room[c.deviceID] = c
	return h.snapshotLocked(c.userID, c.deviceID)
}

func (h *SignalingHub) updatePresence(userID, deviceID string, p SignalPeerPresence) ([]*signalClient, SignalPeerPresence) {
	h.mu.Lock()
	defer h.mu.Unlock()
	room := h.rooms[userID]
	if room == nil {
		return nil, p
	}
	c := room[deviceID]
	if c == nil {
		return nil, p
	}
	p.DeviceID = deviceID
	p.Online = true
	p.UpdatedAtMs = time.Now().UnixMilli()
	c.presence = p

	var targets []*signalClient
	for id, peer := range room {
		if id != deviceID {
			targets = append(targets, peer)
		}
	}
	return targets, p
}

func (h *SignalingHub) unregister(c *signalClient) []*signalClient {
	h.mu.Lock()
	defer h.mu.Unlock()
	room := h.rooms[c.userID]
	if room == nil || room[c.deviceID] != c {
		return nil
	}
	delete(room, c.deviceID)
	if len(room) == 0 {
		delete(h.rooms, c.userID)
		return nil
	}
	var targets []*signalClient
	for _, peer := range room {
		targets = append(targets, peer)
	}
	return targets
}

func (h *SignalingHub) findPeer(userID, targetDeviceID string) *signalClient {
	h.mu.RLock()
	defer h.mu.RUnlock()
	room := h.rooms[userID]
	if room == nil {
		return nil
	}
	return room[targetDeviceID]
}

func (h *SignalingHub) listPeers(userID, excludeDeviceID string) []SignalPeerPresence {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.snapshotLocked(userID, excludeDeviceID)
}

func (h *SignalingHub) snapshotLocked(userID, excludeDeviceID string) []SignalPeerPresence {
	room := h.rooms[userID]
	out := make([]SignalPeerPresence, 0, len(room))
	for id, peer := range room {
		if excludeDeviceID != "" && id == excludeDeviceID {
			continue
		}
		if peer.presence.DeviceID != "" {
			out = append(out, peer.presence)
		}
	}
	return out
}

func extractClientIP(r *http.Request) string {
	if xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); xff != "" {
		first := strings.TrimSpace(strings.Split(xff, ",")[0])
		if first != "" {
			return first
		}
	}
	if xri := strings.TrimSpace(r.Header.Get("X-Real-IP")); xri != "" {
		return xri
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		return host
	}
	return r.RemoteAddr
}

// MARK: - HTTP / WebSocket Handlers on RelayServer

func (s *RelayServer) handleSignalWS(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.authenticateRequest(w, r)
	if !ok {
		return
	}
	deviceID := strings.TrimSpace(r.URL.Query().Get("device"))
	if !safeIDRegex.MatchString(deviceID) {
		writeAPIError(w, http.StatusBadRequest, "invalid_device", "valid device query parameter is required")
		return
	}

	ws, err := upgradeWebSocket(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	observedIP := extractClientIP(r)
	client := &signalClient{
		userID:   principal.RoomID,
		deviceID: deviceID,
		ws:       ws,
		presence: SignalPeerPresence{
			DeviceID:         deviceID,
			ObservedPublicIP: observedIP,
			Online:           true,
			UpdatedAtMs:      time.Now().UnixMilli(),
		},
	}

	existingPeers := s.signaling.register(client)
	defer func() {
		remaining := s.signaling.unregister(client)
		_ = ws.Close()
		if len(remaining) > 0 {
			offlineMsg, _ := json.Marshal(SignalServerMessage{
				Type:     "peer_offline",
				UserID:   principal.RoomID,
				DeviceID: deviceID,
				TimeMs:   time.Now().UnixMilli(),
			})
			for _, peer := range remaining {
				_ = peer.ws.WriteText(offlineMsg)
			}
		}
	}()

	// Send immediate snapshot of already-online devices belonging to the SAME xtags.top account
	snapBytes, _ := json.Marshal(SignalServerMessage{
		Type:   "peers_snapshot",
		UserID: principal.RoomID,
		Peers:  existingPeers,
		TimeMs: time.Now().UnixMilli(),
	})
	_ = ws.WriteText(snapBytes)

	for {
		op, payload, err := ws.ReadMessage(256 * 1024)
		if err != nil {
			return
		}
		if op != wsOpText && op != wsOpBinary {
			continue
		}
		var msg SignalClientMessage
		if json.Unmarshal(payload, &msg) != nil {
			continue
		}

		switch msg.Type {
		case "register":
			if msg.Presence == nil {
				continue
			}
			p := *msg.Presence
			if p.ObservedPublicIP == "" {
				p.ObservedPublicIP = observedIP
			}
			targets, stored := s.signaling.updatePresence(principal.RoomID, deviceID, p)
			upsertBytes, _ := json.Marshal(SignalServerMessage{
				Type:   "peer_upsert",
				UserID: principal.RoomID,
				Peer:   &stored,
				TimeMs: time.Now().UnixMilli(),
			})
			for _, peer := range targets {
				_ = peer.ws.WriteText(upsertBytes)
			}

		case "signal":
			targetID := strings.TrimSpace(msg.TargetDeviceID)
			if targetID == "" || targetID == deviceID {
				continue
			}
			if target := s.signaling.findPeer(principal.RoomID, targetID); target != nil {
				fwd, _ := json.Marshal(SignalServerMessage{
					Type:         "signal",
					UserID:       principal.RoomID,
					FromDeviceID: deviceID,
					Kind:         msg.Kind,
					Payload:      msg.Payload,
					TimeMs:       time.Now().UnixMilli(),
				})
				_ = target.ws.WriteText(fwd)
			}

		case "ping":
			pong, _ := json.Marshal(SignalServerMessage{
				Type:   "pong",
				TimeMs: time.Now().UnixMilli(),
			})
			_ = ws.WriteText(pong)
		}
	}
}

func (s *RelayServer) handleSignalPeers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	principal, ok := s.authenticateRequestOrAdmin(w, r)
	if !ok {
		return
	}
	exclude := strings.TrimSpace(r.URL.Query().Get("excludeDevice"))
	peers := s.signaling.listPeers(principal.RoomID, exclude)
	writeJSON(w, http.StatusOK, map[string]any{
		"userID": principal.RoomID,
		"peers":  peers,
		"timeMs": time.Now().UnixMilli(),
	})
}
