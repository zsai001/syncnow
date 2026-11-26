package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func newMockXTagsAPI(t *testing.T, verifyCalls *atomic.Int32) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth/me" {
			http.NotFound(w, r)
			return
		}
		if verifyCalls != nil {
			verifyCalls.Add(1)
		}
		auth := r.Header.Get("Authorization")
		switch auth {
		case "Bearer xtags_ext_alice":
			writeJSON(w, http.StatusOK, map[string]any{
				"authenticated": true,
				"user": map[string]any{
					"id":          "usr_alice",
					"email":       "alice@xtags.top",
					"displayName": "Alice",
					"providers":   []string{"x"},
				},
			})
		case "Bearer xtags_ext_bob":
			writeJSON(w, http.StatusOK, map[string]any{
				"authenticated": true,
				"user": map[string]any{
					"id":          "usr_bob",
					"email":       "bob@xtags.top",
					"displayName": "Bob",
					"providers":   []string{"github"},
				},
			})
		default:
			writeJSON(w, http.StatusOK, map[string]any{
				"authenticated": false,
				"user":          nil,
			})
		}
	}))
}

// Minimal client-side RFC 6455 WebSocket helper for stdlib-only Go tests.
type testWSClient struct {
	conn net.Conn
	br   *bufio.Reader
}

func dialTestWS(t *testing.T, serverURL, path, bearerToken string) *testWSClient {
	t.Helper()
	addr := strings.TrimPrefix(serverURL, "http://")
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial ws failed: %v", err)
	}
	keyBytes := make([]byte, 16)
	_, _ = rand.Read(keyBytes)
	key := base64.StdEncoding.EncodeToString(keyBytes)

	req := "GET " + path + " HTTP/1.1\r\n" +
		"Host: " + addr + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + key + "\r\n" +
		"Sec-WebSocket-Version: 13\r\n"
	if bearerToken != "" {
		req += "Authorization: Bearer " + bearerToken + "\r\n"
	}
	req += "\r\n"

	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write handshake: %v", err)
	}
	br := bufio.NewReader(conn)
	statusLine, err := br.ReadString('\n')
	if err != nil || !strings.Contains(statusLine, "101") {
		t.Fatalf("expected 101 Switching Protocols, got %q (err=%v)", statusLine, err)
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read header: %v", err)
		}
		if line == "\r\n" {
			break
		}
	}
	return &testWSClient{conn: conn, br: br}
}

func (c *testWSClient) sendJSON(t *testing.T, v any) {
	t.Helper()
	payload, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var mask [4]byte
	_, _ = rand.Read(mask[:])
	var hdr []byte
	hdr = append(hdr, 0x80|wsOpText)
	n := len(payload)
	switch {
	case n < 126:
		hdr = append(hdr, 0x80|byte(n))
	default:
		hdr = append(hdr, 0x80|126, byte(n>>8), byte(n))
	}
	hdr = append(hdr, mask[:]...)
	masked := make([]byte, n)
	for i := range payload {
		masked[i] = payload[i] ^ mask[i%4]
	}
	if _, err := c.conn.Write(append(hdr, masked...)); err != nil {
		t.Fatalf("ws write: %v", err)
	}
}

func (c *testWSClient) readServerMsg(t *testing.T) SignalServerMessage {
	t.Helper()
	_ = c.conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	var h [2]byte
	if _, err := io.ReadFull(c.br, h[:]); err != nil {
		t.Fatalf("read ws header: %v", err)
	}
	length := int(h[1] & 0x7F)
	if length == 126 {
		var ext [2]byte
		if _, err := io.ReadFull(c.br, ext[:]); err != nil {
			t.Fatalf("read ext16: %v", err)
		}
		length = int(binary.BigEndian.Uint16(ext[:]))
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(c.br, buf); err != nil {
		t.Fatalf("read payload: %v", err)
	}
	var msg SignalServerMessage
	if err := json.Unmarshal(buf, &msg); err != nil {
		t.Fatalf("decode signal msg: %v (%s)", err, string(buf))
	}
	return msg
}

func (c *testWSClient) close() { _ = c.conn.Close() }

func TestXTagsAuthCachingAndOwnerLock(t *testing.T) {
	var calls atomic.Int32
	mockXTags := newMockXTagsAPI(t, &calls)
	defer mockXTags.Close()

	relay := NewRelayServerWithOptions(t.TempDir(), "", mockXTags.URL, "usr_alice", 100, 1024*1024, time.Hour)
	srv := httptest.NewServer(relay.Handler())
	defer srv.Close()

	// 1. Alice succeeds and triggers exactly 1 upstream xtags verification call (cached on repeat)
	for i := 0; i < 3; i++ {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/sync?group=grp1", nil)
		req.Header.Set("Authorization", "Bearer xtags_ext_alice")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("alice sync failed: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 for alice, got %d", resp.StatusCode)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("expected cached xtags auth (1 upstream call), got %d", calls.Load())
	}

	// 2. Bob is valid on xtags.top, but blocked by --allow-user usr_alice (403)
	reqBob, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/sync?group=grp1", nil)
	reqBob.Header.Set("Authorization", "Bearer xtags_ext_bob")
	respBob, _ := http.DefaultClient.Do(reqBob)
	respBob.Body.Close()
	if respBob.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for non-owner bob, got %d", respBob.StatusCode)
	}

	// 3. Invalid token gets 401
	reqBad, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/sync?group=grp1", nil)
	reqBad.Header.Set("Authorization", "Bearer invalid_tok")
	respBad, _ := http.DefaultClient.Do(reqBad)
	respBad.Body.Close()
	if respBad.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for invalid token, got %d", respBad.StatusCode)
	}
}

func TestSameAccountSignalingAndRoomIsolation(t *testing.T) {
	mockXTags := newMockXTagsAPI(t, nil)
	defer mockXTags.Close()

	relay := NewRelayServerWithOptions(t.TempDir(), "", mockXTags.URL, "", 100, 1024*1024, time.Hour)
	srv := httptest.NewServer(relay.Handler())
	defer srv.Close()

	// Alice Mac #1 connects & registers LAN + ZeroTier endpoints
	alice1 := dialTestWS(t, srv.URL, "/v1/signal/ws?device=dev-alice-1", "xtags_ext_alice")
	defer alice1.close()
	snap1 := alice1.readServerMsg(t)
	if snap1.Type != "peers_snapshot" || len(snap1.Peers) != 0 {
		t.Fatalf("expected empty initial snapshot, got %+v", snap1)
	}
	alice1.sendJSON(t, SignalClientMessage{
		Type: "register",
		Presence: &SignalPeerPresence{
			DeviceID:   "dev-alice-1",
			DeviceName: "MacBook Air",
			Platform:   "macOS",
			LANEndpoints: []SignalEndpoint{
				{Host: "192.168.31.10", TCPPort: 51820, UDPPort: 51821},
				{Host: "10.147.19.10", TCPPort: 51820, UDPPort: 51821},
			},
			TCPPort: 51820,
			UDPPort: 51821,
		},
	})

	// Bob connects under a DIFFERENT account — MUST NOT see Alice's device!
	bob1 := dialTestWS(t, srv.URL, "/v1/signal/ws?device=dev-bob-1", "xtags_ext_bob")
	defer bob1.close()
	snapBob := bob1.readServerMsg(t)
	if snapBob.Type != "peers_snapshot" || len(snapBob.Peers) != 0 {
		t.Fatalf("cross-account isolation violation: bob saw %+v", snapBob.Peers)
	}

	// Alice Mac #2 connects — MUST immediately receive Mac #1 in snapshot!
	alice2 := dialTestWS(t, srv.URL, "/v1/signal/ws?device=dev-alice-2", "xtags_ext_alice")
	defer alice2.close()
	snap2 := alice2.readServerMsg(t)
	if snap2.Type != "peers_snapshot" || len(snap2.Peers) != 1 || snap2.Peers[0].DeviceID != "dev-alice-1" {
		t.Fatalf("alice2 should see alice1 immediately, got %+v", snap2)
	}

	// Alice Mac #2 registers & Alice Mac #1 receives peer_upsert
	alice2.sendJSON(t, SignalClientMessage{
		Type: "register",
		Presence: &SignalPeerPresence{
			DeviceID:   "dev-alice-2",
			DeviceName: "Mac mini 1",
			Platform:   "macOS",
			LANEndpoints: []SignalEndpoint{
				{Host: "10.147.19.21", TCPPort: 51820, UDPPort: 51821},
			},
			TCPPort: 51820,
		},
	})
	upsert := alice1.readServerMsg(t)
	if upsert.Type != "peer_upsert" || upsert.Peer == nil || upsert.Peer.DeviceID != "dev-alice-2" {
		t.Fatalf("expected peer_upsert for alice2, got %+v", upsert)
	}

	// Alice Mac #1 sends a targeted direct-connect signal to Alice Mac #2
	alice1.sendJSON(t, SignalClientMessage{
		Type:           "signal",
		TargetDeviceID: "dev-alice-2",
		Kind:           "punch_probe",
		Payload:        `{"nonce":"abc123"}`,
	})
	sig := alice2.readServerMsg(t)
	if sig.Type != "signal" || sig.FromDeviceID != "dev-alice-1" || sig.Kind != "punch_probe" {
		t.Fatalf("expected relayed signal from alice1, got %+v", sig)
	}

	// REST /v1/signal/peers also lists same-account online peers
	reqPeers, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/signal/peers?excludeDevice=dev-alice-1", nil)
	reqPeers.Header.Set("Authorization", "Bearer xtags_ext_alice")
	respPeers, err := http.DefaultClient.Do(reqPeers)
	if err != nil || respPeers.StatusCode != http.StatusOK {
		t.Fatalf("GET /v1/signal/peers failed: %v", err)
	}
	var peersResp struct {
		UserID string               `json:"userID"`
		Peers  []SignalPeerPresence `json:"peers"`
	}
	_ = json.NewDecoder(respPeers.Body).Decode(&peersResp)
	respPeers.Body.Close()
	if peersResp.UserID != "usr_alice" || len(peersResp.Peers) != 1 || peersResp.Peers[0].DeviceID != "dev-alice-2" {
		t.Fatalf("unexpected REST peers response: %+v", peersResp)
	}
}

func TestClipboardBlobsAndUpdatesWithXTagsAuth(t *testing.T) {
	mockXTags := newMockXTagsAPI(t, nil)
	defer mockXTags.Close()

	relay := NewRelayServerWithOptions(t.TempDir(), "admin-secret", mockXTags.URL, "", 100, 1024*1024, time.Hour)
	srv := httptest.NewServer(relay.Handler())
	defer srv.Close()

	// 1. E2EE Blob upload & download authenticated by xtags.top Bearer token
	blobData := []byte("encrypted-file-bytes-chacha20")
	upReq, _ := http.NewRequest(http.MethodPut, srv.URL+"/v1/blobs/blob-1?group=grp_alice", bytes.NewReader(blobData))
	upReq.Header.Set("Authorization", "Bearer xtags_ext_alice")
	upResp, err := http.DefaultClient.Do(upReq)
	if err != nil || upResp.StatusCode != http.StatusCreated {
		t.Fatalf("blob upload failed: %v status=%v", err, upResp)
	}
	upResp.Body.Close()

	dlReq, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/blobs/blob-1?group=grp_alice", nil)
	dlReq.Header.Set("Authorization", "Bearer xtags_ext_alice")
	dlResp, _ := http.DefaultClient.Do(dlReq)
	gotBlob, _ := io.ReadAll(dlResp.Body)
	dlResp.Body.Close()
	if !bytes.Equal(gotBlob, blobData) {
		t.Fatalf("blob mismatch: %q vs %q", gotBlob, blobData)
	}

	// 2. Updates admin publish & force-update check remain 100% functional
	pubPayload := `{"platform":"macos","arch":"arm64","channel":"stable","latestVersion":"0.3.0","latestBuild":3,"minRequiredVersion":"0.2.0","forceUpdate":false,"downloadURL":"/v1/updates/files/SyncNow.zip","sha256":"abc"}`
	pubReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/admin/updates", strings.NewReader(pubPayload))
	pubReq.Header.Set("Authorization", "Bearer admin-secret")
	pubReq.Header.Set("Content-Type", "application/json")
	pubResp, _ := http.DefaultClient.Do(pubReq)
	pubResp.Body.Close()
	if pubResp.StatusCode != http.StatusOK {
		t.Fatalf("admin update publish failed: %d", pubResp.StatusCode)
	}

	chkResp, _ := http.Get(srv.URL + "/v1/updates/check?platform=macos&arch=arm64&channel=stable&version=0.1.0&build=1")
	var chk UpdateCheckResponse
	_ = json.NewDecoder(chkResp.Body).Decode(&chk)
	chkResp.Body.Close()
	if !chk.HasUpdate || !chk.ForceUpdate || chk.LatestVersion != "0.3.0" {
		t.Fatalf("expected force update for 0.1.0 < minRequired 0.2.0, got %+v", chk)
	}
}

func TestWebSetupWizardAndOwnerProtection(t *testing.T) {
	mockXTags := newMockXTagsAPI(t, nil)
	defer mockXTags.Close()

	relay := NewRelayServerWithOptions(t.TempDir(), "", mockXTags.URL, "", 100, 1024*1024, time.Hour)
	srv := httptest.NewServer(relay.Handler())
	defer srv.Close()

	// 1. Before setup: / redirects to /setup and /setup renders built-in HTML Web Setup UI
	noRedirectClient := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	rootBeforeResp, err := noRedirectClient.Get(srv.URL + "/")
	if err != nil || rootBeforeResp.StatusCode != http.StatusFound || rootBeforeResp.Header.Get("Location") != "/setup" {
		t.Fatalf("expected GET / before setup to 302 -> /setup, got err=%v status=%v loc=%q", err, rootBeforeResp, rootBeforeResp.Header.Get("Location"))
	}
	rootBeforeResp.Body.Close()

	pageResp, err := http.Get(srv.URL + "/setup")
	if err != nil || pageResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /setup failed: %v status=%v", err, pageResp)
	}
	pageBytes, _ := io.ReadAll(pageResp.Body)
	pageResp.Body.Close()
	if !strings.Contains(string(pageBytes), "SyncNow Relay") {
		t.Fatalf("expected setup HTML page")
	}

	// Unauthenticated /health is denied by default (401)
	unauthHealth, err := http.Get(srv.URL + "/health")
	if err != nil || unauthHealth.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected unauthenticated /health to return 401, got err=%v status=%v", err, unauthHealth)
	}
	unauthHealth.Body.Close()

	// 2. Initially uninitialized
	stResp, _ := http.Get(srv.URL + "/v1/setup/status")
	var st1 map[string]any
	_ = json.NewDecoder(stResp.Body).Decode(&st1)
	stResp.Body.Close()
	if st1["initialized"] != false {
		t.Fatalf("expected initialized=false before setup, got %+v", st1)
	}

	// 3. Alice completes Web Setup binding herself as owner (xtags_owner mode)
	setupBody := `{"siteName":"Alice Relay","authMode":"xtags_owner","authAPI":"` + mockXTags.URL + `","xtagsToken":"xtags_ext_alice","allowUsers":["usr_alice"],"maxEnvelopes":300,"maxBlobMB":20,"blobTTLDays":5}`
	cResp, err := http.Post(srv.URL+"/v1/setup/complete", "application/json", strings.NewReader(setupBody))
	if err != nil || cResp.StatusCode != http.StatusOK {
		t.Fatalf("POST /v1/setup/complete failed: %v status=%v", err, cResp)
	}
	cResp.Body.Close()

	// 4. After setup: Unauthenticated GET /, /health, /v1/setup/status, and /v1/setup/relay-update MUST return 401 with zero owner leak!
	for _, p := range []string{"/", "/health", "/v1/setup/status", "/v1/setup/relay-update"} {
		r, err := noRedirectClient.Get(srv.URL + p)
		if err != nil {
			t.Fatalf("GET %s failed: %v", p, err)
		}
		raw, _ := io.ReadAll(r.Body)
		r.Body.Close()
		if r.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected 401 for unauthenticated GET %s after setup, got %d (%s)", p, r.StatusCode, string(raw))
		}
		if strings.Contains(string(raw), "Alice") || strings.Contains(string(raw), "usr_alice") {
			t.Fatalf("unauthenticated GET %s leaked owner info: %s", p, string(raw))
		}
	}

	// 4b. Browser visit to GET / with Accept: text/html still returns 401 + zero owner leak,
	//     but renders the static HTML unlock console instead of raw JSON.
	browserReq, _ := http.NewRequest(http.MethodGet, srv.URL+"/", nil)
	browserReq.Header.Set("Accept", "text/html,application/xhtml+xml")
	browserResp, err := noRedirectClient.Do(browserReq)
	if err != nil {
		t.Fatalf("browser GET / failed: %v", err)
	}
	browserBody, _ := io.ReadAll(browserResp.Body)
	browserResp.Body.Close()
	if browserResp.StatusCode != http.StatusUnauthorized || !strings.Contains(browserResp.Header.Get("Content-Type"), "text/html") {
		t.Fatalf("expected 401 text/html for browser GET /, got %d (%q)", browserResp.StatusCode, browserResp.Header.Get("Content-Type"))
	}
	if !strings.Contains(string(browserBody), "SyncNow Relay") || strings.Contains(string(browserBody), "Alice") || strings.Contains(string(browserBody), "usr_alice") {
		t.Fatalf("browser GET / returned unexpected body or leaked owner info")
	}

	// Trailing slash /setup/ redirects to /setup, and /favicon.ico returns 204
	slashResp, err := noRedirectClient.Get(srv.URL + "/setup/")
	if err != nil || slashResp.StatusCode != http.StatusFound || slashResp.Header.Get("Location") != "/setup" {
		t.Fatalf("expected GET /setup/ -> 302 /setup, got err=%v status=%v loc=%q", err, slashResp, slashResp.Header.Get("Location"))
	}
	slashResp.Body.Close()

	favResp, err := noRedirectClient.Get(srv.URL + "/favicon.ico")
	if err != nil || favResp.StatusCode != http.StatusNoContent {
		t.Fatalf("expected GET /favicon.ico -> 204, got err=%v status=%v", err, favResp)
	}
	favResp.Body.Close()

	// 5. After setup: Bob CANNOT access /, verify-xtags, hijack /v1/setup/complete (401) OR use relay data API (403)
	bobVerifyResp, _ := http.Post(srv.URL+"/v1/setup/verify-xtags", "application/json", strings.NewReader(`{"token":"xtags_ext_bob"}`))
	bobVerifyResp.Body.Close()
	if bobVerifyResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bob should get 401 on /v1/setup/verify-xtags after setup, got %d", bobVerifyResp.StatusCode)
	}

	hijackReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/setup/complete", strings.NewReader(`{"authMode":"xtags_multi","xtagsToken":"xtags_ext_bob"}`))
	hijackReq.Header.Set("Authorization", "Bearer xtags_ext_bob")
	hijackReq.Header.Set("Content-Type", "application/json")
	hijackResp, _ := http.DefaultClient.Do(hijackReq)
	hijackResp.Body.Close()
	if hijackResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bob should be blocked from hijacking setup (expected 401), got %d", hijackResp.StatusCode)
	}

	bobSyncReq, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/sync?group=grp1", nil)
	bobSyncReq.Header.Set("Authorization", "Bearer xtags_ext_bob")
	bobSyncResp, _ := http.DefaultClient.Do(bobSyncReq)
	bobSyncResp.Body.Close()
	if bobSyncResp.StatusCode != http.StatusForbidden {
		t.Fatalf("bob should get 403 after Alice locked relay via web setup, got %d", bobSyncResp.StatusCode)
	}

	// 6. Alice IS recognized as admin on /v1/setup/status and succeeds on /health and /v1/sync
	aliceHealthReq, _ := http.NewRequest(http.MethodGet, srv.URL+"/health", nil)
	aliceHealthReq.Header.Set("Authorization", "Bearer xtags_ext_alice")
	aliceHealthResp, _ := http.DefaultClient.Do(aliceHealthReq)
	aliceHealthResp.Body.Close()
	if aliceHealthResp.StatusCode != http.StatusOK {
		t.Fatalf("expected alice /health 200 after setup, got %d", aliceHealthResp.StatusCode)
	}

	aliceStatusReq, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/setup/status", nil)
	aliceStatusReq.Header.Set("Authorization", "Bearer xtags_ext_alice")
	aliceStatusResp, _ := http.DefaultClient.Do(aliceStatusReq)
	var st2 map[string]any
	_ = json.NewDecoder(aliceStatusResp.Body).Decode(&st2)
	aliceStatusResp.Body.Close()
	if aliceStatusResp.StatusCode != http.StatusOK || st2["initialized"] != true || st2["isAdmin"] != true || st2["siteName"] != "Alice Relay" {
		t.Fatalf("expected alice admin status after setup, got status=%d body=%+v", aliceStatusResp.StatusCode, st2)
	}

	// 7. Explicit --admin-token works for /v1/setup/status, /v1/setup/relay-update, /health, and /v1/signal/peers
	relay.setAdminToken("super-admin-token-123")
	for _, p := range []string{"/v1/setup/status", "/v1/setup/relay-update", "/health", "/v1/signal/peers"} {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+p, nil)
		req.Header.Set("Authorization", "Bearer super-admin-token-123")
		resp, err := http.DefaultClient.Do(req)
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 for adminToken on %s, got err=%v status=%v", p, err, resp)
		}
		resp.Body.Close()
	}
}

func TestRelayWSPingPongAndSameDeviceReconnectReplacement(t *testing.T) {
	relay := NewRelayServerWithOptions(t.TempDir(), "ws-tok", "", "", 100, 1024*1024, time.Hour)
	srv := httptest.NewServer(relay.Handler())
	defer srv.Close()

	// 1. Connect device-a and verify app-level JSON ping -> pong on /ws
	wsA1 := dialTestWS(t, srv.URL, "/ws?group=grp_ping&device=dev-a", "ws-tok")
	defer wsA1.close()
	wsA1.sendJSON(t, map[string]string{"type": "ping"})
	pong := wsA1.readServerMsg(t)
	if pong.Type != "pong" {
		t.Fatalf("expected pong from /ws ping, got %+v", pong)
	}

	// 2. Reconnect same device-a -> old socket is closed cleanly, new socket stays registered
	wsA2 := dialTestWS(t, srv.URL, "/ws?group=grp_ping&device=dev-a", "ws-tok")
	defer wsA2.close()
	wsA2.sendJSON(t, map[string]string{"type": "ping"})
	pong2 := wsA2.readServerMsg(t)
	if pong2.Type != "pong" {
		t.Fatalf("expected pong from replacement /ws socket, got %+v", pong2)
	}
}
