package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func (c *testWSClient) sendBinary(t *testing.T, payload []byte) {
	t.Helper()
	var mask [4]byte
	_, _ = rand.Read(mask[:])
	var hdr []byte
	hdr = append(hdr, 0x80|wsOpBinary)
	n := len(payload)
	switch {
	case n < 126:
		hdr = append(hdr, 0x80|byte(n))
	case n <= 65535:
		hdr = append(hdr, 0x80|126, byte(n>>8), byte(n))
	default:
		var ext [8]byte
		binary.BigEndian.PutUint64(ext[:], uint64(n))
		hdr = append(hdr, 0x80|127)
		hdr = append(hdr, ext[:]...)
	}
	hdr = append(hdr, mask[:]...)
	masked := make([]byte, n)
	for i := range payload {
		masked[i] = payload[i] ^ mask[i%4]
	}
	if _, err := c.conn.Write(append(hdr, masked...)); err != nil {
		t.Fatalf("ws binary write: %v", err)
	}
}

func (c *testWSClient) readRawFrame(t *testing.T) (byte, []byte) {
	t.Helper()
	_ = c.conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	var h [2]byte
	if _, err := io.ReadFull(c.br, h[:]); err != nil {
		t.Fatalf("read ws header: %v", err)
	}
	op := h[0] & 0x0F
	length := int(h[1] & 0x7F)
	switch length {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(c.br, ext[:]); err != nil {
			t.Fatalf("read ext16: %v", err)
		}
		length = int(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(c.br, ext[:]); err != nil {
			t.Fatalf("read ext64: %v", err)
		}
		length = int(binary.BigEndian.Uint64(ext[:]))
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(c.br, buf); err != nil {
		t.Fatalf("read payload: %v", err)
	}
	return op, buf
}

func TestTmpChunkedUploadResumeRangeAckLRUEvictionAndWebPolicy(t *testing.T) {
	relay := NewRelayServer(t.TempDir(), "owner-tok-123456", 100, 10*1024*1024, time.Hour)
	srv := httptest.NewServer(relay.Handler())
	defer srv.Close()

	// 0. Public /ping works unauthenticated for Docker/VPS healthchecks
	pingResp, err := http.Get(srv.URL + "/ping")
	if err != nil || pingResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on /ping, got err=%v resp=%v", err, pingResp)
	}
	pingResp.Body.Close()

	// 1. Update Tmp policy dynamically via /v1/setup/tmp-policy (2 MB file cap, 2 MB total cap, 6h TTL, 0m ACK burn)
	policyBody := `{"maxTmpFileMB":2,"maxTmpTotalMB":2,"tmpTTLHours":6,"tmpAckGraceMinutes":30}`
	polReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/setup/tmp-policy", strings.NewReader(policyBody))
	polReq.Header.Set("Authorization", "Bearer owner-tok-123456")
	polReq.Header.Set("Content-Type", "application/json")
	polResp, err := http.DefaultClient.Do(polReq)
	if err != nil || polResp.StatusCode != http.StatusOK {
		t.Fatalf("tmp-policy update failed: %v status=%v", err, polResp)
	}
	polResp.Body.Close()

	// 2. Initialize a 3-chunk transfer (chunkPlain=65536 -> chunkCipher=65552; totalPlain=150000 -> totalCipher=150048)
	chunkPlain := 65536
	chunkCipher := chunkPlain + TmpChunkAEADTagBytes
	totalPlain := 150000
	totalChunks := 3
	totalCipher := totalPlain + totalChunks*TmpChunkAEADTagBytes

	rawCipher := make([]byte, totalCipher)
	_, _ = rand.Read(rawCipher)

	initPayload := `{
		"transferID":"tx-alpha-001",
		"groupHash":"grp_tmp_test",
		"senderDeviceID":"mac-pro",
		"totalPlainBytes":150000,
		"totalCipherBytes":150048,
		"chunkPlainBytes":65536,
		"totalChunks":3
	}`
	initReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/tmp/init", strings.NewReader(initPayload))
	initReq.Header.Set("Authorization", "Bearer owner-tok-123456")
	initReq.Header.Set("Content-Type", "application/json")
	initResp, err := http.DefaultClient.Do(initReq)
	if err != nil || initResp.StatusCode != http.StatusOK {
		t.Fatalf("tmp init failed: %v status=%v", err, initResp)
	}
	var initData struct {
		Ticket         string `json:"ticket"`
		UploadedChunks []int  `json:"uploadedChunks"`
	}
	_ = json.NewDecoder(initResp.Body).Decode(&initData)
	initResp.Body.Close()
	if initData.Ticket == "" || len(initData.UploadedChunks) != 0 {
		t.Fatalf("unexpected initData: %+v", initData)
	}

	// 3. Upload part 2 first (out-of-order!) using ONLY X-SyncNow-Ticket, then verify resumable init reports [2]
	part2Slice := rawCipher[2*chunkCipher:]
	putPart := func(idx int, data []byte) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPut, srv.URL+"/v1/tmp/tx-alpha-001/parts/"+string(rune('0'+idx))+"?group=grp_tmp_test", bytes.NewReader(data))
		req.Header.Set("X-SyncNow-Ticket", initData.Ticket)
		resp, err := http.DefaultClient.Do(req)
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("upload part %d failed: %v status=%v", idx, err, resp)
		}
		resp.Body.Close()
	}
	putPart(2, part2Slice)

	resumeReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/tmp/init", strings.NewReader(initPayload))
	resumeReq.Header.Set("Authorization", "Bearer owner-tok-123456")
	resumeResp, _ := http.DefaultClient.Do(resumeReq)
	var resumeData struct {
		UploadedChunks []int `json:"uploadedChunks"`
	}
	_ = json.NewDecoder(resumeResp.Body).Decode(&resumeData)
	resumeResp.Body.Close()
	if len(resumeData.UploadedChunks) != 1 || resumeData.UploadedChunks[0] != 2 {
		t.Fatalf("expected resumable uploadedChunks=[2], got %+v", resumeData.UploadedChunks)
	}

	// Upload remaining parts 0 and 1, then complete
	putPart(0, rawCipher[0:chunkCipher])
	putPart(1, rawCipher[chunkCipher:2*chunkCipher])

	compReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/tmp/tx-alpha-001/complete", strings.NewReader(`{"groupHash":"grp_tmp_test"}`))
	compReq.Header.Set("Authorization", "Bearer owner-tok-123456")
	compResp, err := http.DefaultClient.Do(compReq)
	if err != nil || compResp.StatusCode != http.StatusOK {
		t.Fatalf("complete failed: %v status=%v", err, compResp)
	}
	compResp.Body.Close()

	// 4. Verify per-part GET and HTTP Range 206 Partial Content streaming match byte-for-byte
	p1Req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/tmp/tx-alpha-001/parts/1?group=grp_tmp_test", nil)
	p1Req.Header.Set("Authorization", "Bearer owner-tok-123456")
	p1Resp, _ := http.DefaultClient.Do(p1Req)
	gotP1, _ := io.ReadAll(p1Resp.Body)
	p1Resp.Body.Close()
	if !bytes.Equal(gotP1, rawCipher[chunkCipher:2*chunkCipher]) {
		t.Fatalf("part 1 bytes mismatch (len=%d)", len(gotP1))
	}

	rangeReq, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/tmp/tx-alpha-001?group=grp_tmp_test", nil)
	rangeReq.Header.Set("Authorization", "Bearer owner-tok-123456")
	rangeReq.Header.Set("Range", "bytes=100-999")
	rangeResp, _ := http.DefaultClient.Do(rangeReq)
	gotRange, _ := io.ReadAll(rangeResp.Body)
	rangeResp.Body.Close()
	if rangeResp.StatusCode != http.StatusPartialContent || !bytes.Equal(gotRange, rawCipher[100:1000]) {
		t.Fatalf("HTTP Range 206 failed: status=%d len=%d", rangeResp.StatusCode, len(gotRange))
	}

	// 5. ACK marks tx-alpha-001 as received; then uploading a 1.95 MB second file within the 2 MB total cap
	//    must automatically LRU-evict tx-alpha-001!
	ackReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/tmp/tx-alpha-001/ack", strings.NewReader(`{"groupHash":"grp_tmp_test","deviceID":"win-pc"}`))
	ackReq.Header.Set("Authorization", "Bearer owner-tok-123456")
	ackResp, _ := http.DefaultClient.Do(ackReq)
	ackResp.Body.Close()

	bigPlain := 1980000
	bigCipher := bigPlain + 1*TmpChunkAEADTagBytes
	init2 := `{
		"transferID":"tx-beta-002",
		"groupHash":"grp_tmp_test",
		"senderDeviceID":"mac-pro",
		"totalPlainBytes":1980000,
		"totalCipherBytes":` + strconvItoa(bigCipher) + `,
		"chunkPlainBytes":2097152,
		"totalChunks":1
	}`
	init2Req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/tmp/init", strings.NewReader(init2))
	init2Req.Header.Set("Authorization", "Bearer owner-tok-123456")
	init2Resp, err := http.DefaultClient.Do(init2Req)
	if err != nil || init2Resp.StatusCode != http.StatusOK {
		t.Fatalf("expected LRU eviction to make room for tx-beta-002, got err=%v status=%v", err, init2Resp)
	}
	init2Resp.Body.Close()

	// Confirm tx-alpha-001 was evicted (404)
	evictedReq, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/tmp/tx-alpha-001?group=grp_tmp_test", nil)
	evictedReq.Header.Set("Authorization", "Bearer owner-tok-123456")
	evictedResp, _ := http.DefaultClient.Do(evictedReq)
	evictedResp.Body.Close()
	if evictedResp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected evicted tx-alpha-001 to return 404, got %d", evictedResp.StatusCode)
	}

	// 6. Purge all tmp files via /v1/setup/purge-tmp
	purgeReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/setup/purge-tmp", nil)
	purgeReq.Header.Set("Authorization", "Bearer owner-tok-123456")
	purgeResp, _ := http.DefaultClient.Do(purgeReq)
	var purgeBody struct {
		OK          bool `json:"ok"`
		PurgedCount int  `json:"purgedCount"`
	}
	_ = json.NewDecoder(purgeResp.Body).Decode(&purgeBody)
	purgeResp.Body.Close()
	if !purgeBody.OK || purgeBody.PurgedCount != 1 {
		t.Fatalf("unexpected purge response: %+v", purgeBody)
	}
}

func TestScopedDeviceTokensVaultAndBinaryTunnel(t *testing.T) {
	mockXTags := newMockXTagsAPI(t, nil)
	defer mockXTags.Close()

	relay := NewRelayServerWithOptions(t.TempDir(), "", mockXTags.URL, "usr_alice", 100, 5*1024*1024, time.Hour)
	srv := httptest.NewServer(relay.Handler())
	defer srv.Close()

	// Complete setup binding usr_alice as owner
	setupBody := `{"siteName":"Alice Vault Relay","authMode":"xtags_owner","authAPI":"` + mockXTags.URL + `","xtagsToken":"xtags_ext_alice","allowUsers":["usr_alice"]}`
	cResp, _ := http.Post(srv.URL+"/v1/setup/complete", "application/json", strings.NewReader(setupBody))
	cResp.Body.Close()

	// 1. Alice desktop mints a scoped device token `snr_dev_...` for her iPhone
	issueReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/auth/device-tokens", strings.NewReader(`{"label":"Alice iPhone"}`))
	issueReq.Header.Set("Authorization", "Bearer xtags_ext_alice")
	issueReq.Header.Set("Content-Type", "application/json")
	issueResp, err := http.DefaultClient.Do(issueReq)
	if err != nil || issueResp.StatusCode != http.StatusOK {
		t.Fatalf("device token issue failed: %v status=%v", err, issueResp)
	}
	var issued struct {
		Token  string            `json:"token"`
		Record DeviceTokenRecord `json:"record"`
	}
	_ = json.NewDecoder(issueResp.Body).Decode(&issued)
	issueResp.Body.Close()
	if !strings.HasPrefix(issued.Token, "snr_dev_") || issued.Record.RoomID != "usr_alice" {
		t.Fatalf("unexpected issued token: %+v", issued)
	}

	// 2. Scoped `snr_dev_...` token CAN access /health & data/signaling routes, but CANNOT access /v1/setup/status (401) or mint tokens (403)!
	devHealthReq, _ := http.NewRequest(http.MethodGet, srv.URL+"/health", nil)
	devHealthReq.Header.Set("Authorization", "Bearer "+issued.Token)
	devHealthResp, _ := http.DefaultClient.Do(devHealthReq)
	devHealthResp.Body.Close()
	if devHealthResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on /health for snr_dev_ token, got %d", devHealthResp.StatusCode)
	}

	devAdminReq, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/setup/status", nil)
	devAdminReq.Header.Set("Authorization", "Bearer "+issued.Token)
	devAdminResp, _ := http.DefaultClient.Do(devAdminReq)
	devAdminResp.Body.Close()
	if devAdminResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected snr_dev_ token to get 401 on admin /v1/setup/status, got %d", devAdminResp.StatusCode)
	}

	devMintReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/auth/device-tokens", strings.NewReader(`{"label":"rogue"}`))
	devMintReq.Header.Set("Authorization", "Bearer "+issued.Token)
	devMintResp, _ := http.DefaultClient.Do(devMintReq)
	devMintResp.Body.Close()
	if devMintResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected snr_dev_ token to get 403 minting tokens, got %d", devMintResp.StatusCode)
	}

	// 3. Group Key Vault: Device B registers X25519 key -> Device A fetches directory & uploads sealed envelope -> Device B retrieves it!
	putB, _ := http.NewRequest(http.MethodPut, srv.URL+"/v1/signal/group-vault", strings.NewReader(`{
		"device": {
			"deviceID": "iphone-b",
			"deviceName": "Alice iPhone",
			"platform": "iOS",
			"signingPublicKeyBase64": "cHVibGljLWtleS1i",
			"x25519PublicKeyBase64": "eDI1NTE5LWI="
		}
	}`))
	putB.Header.Set("Authorization", "Bearer "+issued.Token)
	putBResp, _ := http.DefaultClient.Do(putB)
	putBResp.Body.Close()

	putA, _ := http.NewRequest(http.MethodPut, srv.URL+"/v1/signal/group-vault", strings.NewReader(`{
		"senderDeviceID": "mac-a",
		"envelopes": [{
			"targetDeviceID": "iphone-b",
			"senderDeviceID": "mac-a",
			"senderSigningPublicKeyBase64": "cHVibGljLWtleS1h",
			"ephemeralX25519PubBase64": "ZXBoLXB1Yg==",
			"ciphertextBase64": "c2VhbGVkLWdyb3VwLWtleQ==",
			"groupHash": "grp_hash_123",
			"keyUpdatedAtMs": 1730000099000,
			"signatureBase64": "c2ln"
		}]
	}`))
	putA.Header.Set("Authorization", "Bearer xtags_ext_alice")
	putAResp, _ := http.DefaultClient.Do(putA)
	putAResp.Body.Close()

	getB, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/signal/group-vault?device=iphone-b", nil)
	getB.Header.Set("Authorization", "Bearer "+issued.Token)
	getBResp, _ := http.DefaultClient.Do(getB)
	var vaultData struct {
		Devices       []KnownAccountDevice    `json:"devices"`
		EnvelopeForMe *SealedGroupKeyEnvelope `json:"envelopeForMe"`
	}
	_ = json.NewDecoder(getBResp.Body).Decode(&vaultData)
	getBResp.Body.Close()
	if vaultData.EnvelopeForMe == nil || vaultData.EnvelopeForMe.GroupHash != "grp_hash_123" || len(vaultData.Devices) != 1 {
		t.Fatalf("unexpected group vault response: %+v", vaultData)
	}

	// 4. Binary PeerSession WebSocket Tunnel (`/v1/tunnel/ws`) pairs Alice Mac (`xtags_ext_alice`) & Alice iPhone (`snr_dev_...`) in the SAME room!
	dialWS := dialTestWS(t, srv.URL, "/v1/tunnel/ws?tunnel=tun-99&device=mac-a&peer=iphone-b&role=dial", "xtags_ext_alice")
	defer dialWS.close()
	acceptWS := dialTestWS(t, srv.URL, "/v1/tunnel/ws?tunnel=tun-99&device=iphone-b&peer=mac-a&role=accept", issued.Token)
	defer acceptWS.close()

	op1, ready1 := dialWS.readRawFrame(t)
	op2, ready2 := acceptWS.readRawFrame(t)
	if op1 != wsOpText || !strings.Contains(string(ready1), "tunnel_ready") || op2 != wsOpText || !strings.Contains(string(ready2), "tunnel_ready") {
		t.Fatalf("expected tunnel_ready on both ends, got %q / %q", string(ready1), string(ready2))
	}

	wireAtoB := []byte{0x53, 0x4E, 0x01, 0x01, 0x01, 0x01, 0x00, 0x01, 0xDE, 0xAD, 0xBE, 0xEF}
	dialWS.sendBinary(t, wireAtoB)
	gotOp, gotBytes := acceptWS.readRawFrame(t)
	if gotOp != wsOpBinary || !bytes.Equal(gotBytes, wireAtoB) {
		t.Fatalf("binary tunnel A->B mismatch: op=%d got=%x", gotOp, gotBytes)
	}

	wireBtoA := []byte{0x53, 0x4E, 0x01, 0x02, 0x02, 0x07, 0x00, 0x01, 0xCA, 0xFE}
	acceptWS.sendBinary(t, wireBtoA)
	gotOp2, gotBytes2 := dialWS.readRawFrame(t)
	if gotOp2 != wsOpBinary || !bytes.Equal(gotBytes2, wireBtoA) {
		t.Fatalf("binary tunnel B->A mismatch: op=%d got=%x", gotOp2, gotBytes2)
	}

	// 5. Revoke device token -> immediately returns 401
	revReq, _ := http.NewRequest(http.MethodDelete, srv.URL+"/v1/auth/device-tokens/"+issued.Record.ID, nil)
	revReq.Header.Set("Authorization", "Bearer xtags_ext_alice")
	revResp, _ := http.DefaultClient.Do(revReq)
	revResp.Body.Close()

	afterRevReq, _ := http.NewRequest(http.MethodGet, srv.URL+"/health", nil)
	afterRevReq.Header.Set("Authorization", "Bearer "+issued.Token)
	afterRevResp, _ := http.DefaultClient.Do(afterRevReq)
	afterRevResp.Body.Close()
	if afterRevResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected revoked snr_dev_ token to get 401, got %d", afterRevResp.StatusCode)
	}
}

func strconvItoa(n int) string {
	var buf [32]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if i == len(buf) {
		return "0"
	}
	return string(buf[i:])
}
