package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRelayHealthPushSyncAndBlob(t *testing.T) {
	dir := t.TempDir()
	relay := NewRelayServer(dir, "secret-token", 100, 1024*1024, 24*time.Hour)
	srv := httptest.NewServer(relay.Handler())
	defer srv.Close()

	// Unauthorized check
	resp, err := http.Get(srv.URL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 without token, got %d", resp.StatusCode)
	}

	// Authorized health check
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/health", nil)
	req.Header.Set("Authorization", "Bearer secret-token")
	resp, err = http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("health check failed: %v status=%v", err, resp.StatusCode)
	}

	// Push encrypted envelope
	env := Envelope{
		ID:               "item-1",
		GroupHash:        "group-abc123",
		SenderDeviceID:   "mac-a",
		CreatedAtMs:      time.Now().UnixMilli(),
		CiphertextBase64: "ZW5jcnlwdGVk",
	}
	body, _ := json.Marshal(env)
	pushReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/push", bytes.NewReader(body))
	pushReq.Header.Set("Authorization", "Bearer secret-token")
	pushResp, err := http.DefaultClient.Do(pushReq)
	if err != nil || pushResp.StatusCode != http.StatusOK {
		t.Fatalf("push failed: %v", err)
	}

	// Offline sync pull
	syncReq, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/sync?group=group-abc123&since=0", nil)
	syncReq.Header.Set("Authorization", "Bearer secret-token")
	syncResp, err := http.DefaultClient.Do(syncReq)
	if err != nil || syncResp.StatusCode != http.StatusOK {
		t.Fatalf("sync failed: %v", err)
	}
	var pulled []Envelope
	if err := json.NewDecoder(syncResp.Body).Decode(&pulled); err != nil {
		t.Fatal(err)
	}
	if len(pulled) != 1 || pulled[0].ID != "item-1" || pulled[0].Seq != 1 {
		t.Fatalf("unexpected pulled envelopes: %+v", pulled)
	}

	// Upload & download encrypted blob
	blobData := []byte("opaque-chacha20-ciphertext")
	upReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/blobs/blob-1?group=group-abc123", bytes.NewReader(blobData))
	upReq.Header.Set("Authorization", "Bearer secret-token")
	upResp, err := http.DefaultClient.Do(upReq)
	if err != nil || upResp.StatusCode != http.StatusCreated {
		t.Fatalf("blob upload failed: %v status=%v", err, upResp.StatusCode)
	}

	dlReq, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/blobs/blob-1?group=group-abc123", nil)
	dlReq.Header.Set("Authorization", "Bearer secret-token")
	dlResp, err := http.DefaultClient.Do(dlReq)
	if err != nil || dlResp.StatusCode != http.StatusOK {
		t.Fatalf("blob download failed: %v", err)
	}
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(dlResp.Body)
	if !bytes.Equal(buf.Bytes(), blobData) {
		t.Fatalf("blob mismatch: got %q", buf.String())
	}
}
