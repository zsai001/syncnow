import { DurableObject } from 'cloudflare:workers';
import { sha256Hex, signTmpTicket } from './auth.ts';
import {
  apiError,
  DEFAULT_TMP_CHUNK_PLAIN_BYTES,
  DEVICE_TOKEN_PREFIX,
  jsonResponse,
  MAX_TMP_CHUNKS_PER_TRANSFER,
  SAFE_ID_REGEX,
  TMP_CHUNK_AEAD_TAG_BYTES,
  type DeviceTokenRecord,
  type DynamicRelayConfig,
  type Env,
  type Envelope,
  type KnownAccountDevice,
  type ReleaseEntry,
  type SealedGroupKeyEnvelope,
  type SignalClientMessage,
  type SignalPeerPresence,
  type SignalServerMessage,
  type TmpStatsSummary,
} from './types.ts';

const CHUNK_SIZE_BYTES = 1024 * 1024; // 1 MiB SQLite slice size (safely below CF DO 2 MiB SQLite row limit)

function randomHex(bytesLen: number): string {
  const arr = new Uint8Array(bytesLen);
  crypto.getRandomValues(arr);
  return Array.from(arr, (b) => b.toString(16).padStart(2, '0')).join('');
}

// ============================================================================
// 1. RelayGroupDO — E2EE Clipboard Envelopes + Legacy Blobs + DO SQLite Tmp Slices
// ============================================================================

export class RelayGroupDO extends DurableObject<Env> {
  private initialized = false;
  private dynMaxEnvelopes: number | null = null;
  private dynMaxBlobMB: number | null = null;
  private dynBlobTTLDays: number | null = null;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.ctx.setWebSocketAutoResponse(
      new WebSocketRequestResponsePair('{"type":"ping"}', '{"type":"pong"}'),
    );
  }

  private ensureSchema(): void {
    if (this.initialized) return;
    this.ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS envelopes (
        seq INTEGER PRIMARY KEY AUTOINCREMENT,
        id TEXT NOT NULL,
        group_hash TEXT NOT NULL,
        sender_device_id TEXT NOT NULL,
        created_at_ms INTEGER NOT NULL,
        ciphertext_base64 TEXT NOT NULL,
        blob_id TEXT,
        blob_size INTEGER
      );
      CREATE TABLE IF NOT EXISTS blob_chunks (
        blob_id TEXT NOT NULL,
        chunk_idx INTEGER NOT NULL,
        data BLOB NOT NULL,
        created_at_ms INTEGER NOT NULL,
        PRIMARY KEY (blob_id, chunk_idx)
      );
      CREATE TABLE IF NOT EXISTS tmp_part_slices (
        transfer_id TEXT NOT NULL,
        part_idx INTEGER NOT NULL,
        slice_idx INTEGER NOT NULL,
        data BLOB NOT NULL,
        created_at_ms INTEGER NOT NULL,
        PRIMARY KEY (transfer_id, part_idx, slice_idx)
      );
      CREATE TABLE IF NOT EXISTS group_meta (
        key TEXT PRIMARY KEY,
        val TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_blob_chunks_created ON blob_chunks(created_at_ms);
      CREATE INDEX IF NOT EXISTS idx_tmp_slices_transfer ON tmp_part_slices(transfer_id);
    `);
    this.initialized = true;
  }

  private applyQuotaHeaders(request: Request): void {
    const maxEnv = Number(request.headers.get('X-SyncNow-Max-Envelopes') || '');
    if (Number.isFinite(maxEnv) && maxEnv > 0 && maxEnv <= 5000) {
      this.dynMaxEnvelopes = maxEnv;
    }
    const maxBlob = Number(request.headers.get('X-SyncNow-Max-Blob-MB') || '');
    if (Number.isFinite(maxBlob) && maxBlob > 0 && maxBlob <= 512) {
      this.dynMaxBlobMB = maxBlob;
    }
    const ttlDays = Number(request.headers.get('X-SyncNow-Blob-TTL-Days') || '');
    if (Number.isFinite(ttlDays) && ttlDays > 0 && ttlDays <= 365) {
      if (this.dynBlobTTLDays !== ttlDays) {
        this.dynBlobTTLDays = ttlDays;
        this.ctx.storage.sql.exec(
          'INSERT OR REPLACE INTO group_meta (key, val) VALUES (?, ?)',
          'blob_ttl_days',
          String(ttlDays),
        );
      }
    }
  }

  private maxEnvelopes(): number {
    if (this.dynMaxEnvelopes !== null) return this.dynMaxEnvelopes;
    const n = Number(this.env.SYNCNOW_MAX_ENVELOPES || '500');
    return Number.isFinite(n) && n > 0 ? Math.min(n, 5000) : 500;
  }

  private maxBlobBytes(): number {
    if (this.dynMaxBlobMB !== null) return this.dynMaxBlobMB * 1024 * 1024;
    const mb = Number(this.env.SYNCNOW_MAX_BLOB_MB || '25');
    return (Number.isFinite(mb) && mb > 0 ? mb : 25) * 1024 * 1024;
  }

  private blobTTLMs(): number {
    if (this.dynBlobTTLDays !== null) return this.dynBlobTTLDays * 24 * 60 * 60 * 1000;
    const row = this.ctx.storage.sql
      .exec<{ val: string }>('SELECT val FROM group_meta WHERE key = ?', 'blob_ttl_days')
      .toArray()[0];
    if (row) {
      const persisted = Number(row.val);
      if (Number.isFinite(persisted) && persisted > 0) {
        this.dynBlobTTLDays = persisted;
        return persisted * 24 * 60 * 60 * 1000;
      }
    }
    const days = Number(this.env.SYNCNOW_BLOB_TTL_DAYS || '7');
    return (Number.isFinite(days) && days > 0 ? days : 7) * 24 * 60 * 60 * 1000;
  }

  override async fetch(request: Request): Promise<Response> {
    this.ensureSchema();
    this.applyQuotaHeaders(request);
    const url = new URL(request.url);

    // Internal DO SQLite streaming fallback for `/v1/tmp/*` when Cloudflare R2 is not bound
    if (url.pathname.startsWith('/internal/do-tmp/')) {
      return this.handleInternalDOTmp(request, url);
    }

    if (url.pathname === '/ws') {
      return this.handleWebSocket(request, url);
    }
    if (url.pathname === '/v1/push' && request.method === 'POST') {
      return this.handlePush(request);
    }
    if (url.pathname === '/v1/sync' && request.method === 'GET') {
      return this.handleSync(url);
    }
    if (url.pathname.startsWith('/v1/blobs/')) {
      return this.handleBlob(request, url);
    }
    return apiError(404, 'not_found', 'Not found');
  }

  private async handleInternalDOTmp(request: Request, url: URL): Promise<Response> {
    const rest = url.pathname.slice('/internal/do-tmp/'.length);
    if (rest === 'purge-all' && request.method === 'POST') {
      this.ctx.storage.sql.exec('DELETE FROM tmp_part_slices');
      return jsonResponse({ ok: true });
    }
    const segs = rest.split('/');
    const transferID = segs[0] || '';
    if (!SAFE_ID_REGEX.test(transferID)) {
      return apiError(400, 'invalid_transfer_id', 'invalid transferID');
    }

    if (segs.length === 1 && request.method === 'DELETE') {
      this.ctx.storage.sql.exec('DELETE FROM tmp_part_slices WHERE transfer_id = ?', transferID);
      return jsonResponse({ ok: true });
    }

    // Stream full file across all parts via zero-concatenation ReadableStream
    if (segs.length === 1 && request.method === 'GET') {
      const totalChunks = Number(url.searchParams.get('totalChunks') || '0');
      const totalCipher = Number(url.searchParams.get('totalCipher') || '0');
      if (totalChunks <= 0 || totalCipher <= 0) {
        return apiError(400, 'invalid_params', 'missing chunk counts');
      }
      const sql = this.ctx.storage.sql;
      let curPart = 0;
      let curSlice = 0;
      const stream = new ReadableStream<Uint8Array>({
        pull(controller) {
          while (curPart < totalChunks) {
            const row = sql
              .exec<{ data: ArrayBuffer }>(
                'SELECT data FROM tmp_part_slices WHERE transfer_id = ? AND part_idx = ? AND slice_idx = ?',
                transferID,
                curPart,
                curSlice,
              )
              .toArray()[0];
            if (row) {
              curSlice += 1;
              controller.enqueue(new Uint8Array(row.data));
              return;
            }
            curPart += 1;
            curSlice = 0;
          }
          controller.close();
        },
      });
      return new Response(stream, {
        status: 200,
        headers: {
          'Content-Type': 'application/octet-stream',
          'Content-Length': String(totalCipher),
        },
      });
    }

    if (segs.length === 3 && segs[1] === 'parts') {
      const partIdx = Number(segs[2]);
      if (!Number.isInteger(partIdx) || partIdx < 0) {
        return apiError(400, 'invalid_part', 'invalid part index');
      }

      if (request.method === 'PUT' || request.method === 'POST') {
        const expectedLen = Number(url.searchParams.get('expectedLen') || '0');
        const data = new Uint8Array(await request.arrayBuffer());
        if (expectedLen > 0 && data.byteLength !== expectedLen) {
          return apiError(
            400,
            'part_size_mismatch',
            `expected ${expectedLen} bytes, got ${data.byteLength}`,
          );
        }
        const now = Date.now();
        this.ctx.storage.sql.exec(
          'DELETE FROM tmp_part_slices WHERE transfer_id = ? AND part_idx = ?',
          transferID,
          partIdx,
        );
        let sliceIdx = 0;
        for (let off = 0; off < data.byteLength; off += CHUNK_SIZE_BYTES) {
          const slice = data.subarray(off, Math.min(off + CHUNK_SIZE_BYTES, data.byteLength));
          this.ctx.storage.sql.exec(
            'INSERT INTO tmp_part_slices (transfer_id, part_idx, slice_idx, data, created_at_ms) VALUES (?, ?, ?, ?, ?)',
            transferID,
            partIdx,
            sliceIdx,
            slice,
            now,
          );
          sliceIdx += 1;
        }
        const etag = `do-${partIdx}-${data.byteLength}`;
        return jsonResponse({ partIndex: partIdx, partNumber: partIdx + 1, etag });
      }

      if (request.method === 'GET') {
        const countRow = this.ctx.storage.sql
          .exec<{ cnt: number; total: number }>(
            'SELECT COUNT(*) AS cnt, COALESCE(SUM(LENGTH(data)), 0) AS total FROM tmp_part_slices WHERE transfer_id = ? AND part_idx = ?',
            transferID,
            partIdx,
          )
          .one();
        if (!countRow || countRow.cnt === 0) {
          return apiError(404, 'not_found', 'part not found');
        }
        const sql = this.ctx.storage.sql;
        let sliceIdx = 0;
        const totalSlices = Number(countRow.cnt);
        const stream = new ReadableStream<Uint8Array>({
          pull(controller) {
            if (sliceIdx >= totalSlices) {
              controller.close();
              return;
            }
            const row = sql
              .exec<{ data: ArrayBuffer }>(
                'SELECT data FROM tmp_part_slices WHERE transfer_id = ? AND part_idx = ? AND slice_idx = ?',
                transferID,
                partIdx,
                sliceIdx,
              )
              .toArray()[0];
            sliceIdx += 1;
            if (!row) {
              controller.close();
              return;
            }
            controller.enqueue(new Uint8Array(row.data));
          },
        });
        return new Response(stream, {
          status: 200,
          headers: {
            'Content-Type': 'application/octet-stream',
            'Content-Length': String(countRow.total),
          },
        });
      }
    }

    return apiError(404, 'not_found', 'Not found');
  }

  private handleWebSocket(request: Request, url: URL): Response {
    if (request.headers.get('Upgrade')?.toLowerCase() !== 'websocket') {
      return apiError(426, 'upgrade_required', 'Expected Upgrade: websocket');
    }
    const groupHash = url.searchParams.get('group') || '';
    const deviceID = url.searchParams.get('device') || '';
    if (!SAFE_ID_REGEX.test(groupHash) || !SAFE_ID_REGEX.test(deviceID)) {
      return apiError(400, 'invalid_params', 'invalid group or device');
    }

    for (const existing of this.ctx.getWebSockets(deviceID)) {
      try {
        existing.close(1000, 'Replaced by newer connection');
      } catch {
        // ignore
      }
    }

    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair) as [WebSocket, WebSocket];
    this.ctx.acceptWebSocket(server, [deviceID]);
    server.serializeAttachment({ groupHash, deviceID });
    return new Response(null, { status: 101, webSocket: client });
  }

  override async webSocketMessage(ws: WebSocket, message: string | ArrayBuffer): Promise<void> {
    this.ensureSchema();
    const meta = ws.deserializeAttachment() as { groupHash: string; deviceID: string } | null;
    if (!meta) return;

    const rawText = typeof message === 'string' ? message : new TextDecoder().decode(message);
    let parsed: Envelope & { type?: string };
    try {
      parsed = JSON.parse(rawText) as Envelope & { type?: string };
    } catch {
      return;
    }
    if (parsed.type === 'ping') {
      try {
        ws.send(JSON.stringify({ type: 'pong', timeMs: Date.now() }));
      } catch {
        // ignore
      }
      return;
    }
    if (parsed.groupHash !== meta.groupHash) return;
    parsed.senderDeviceID = meta.deviceID;
    const stored = this.appendEnvelope(parsed);
    this.broadcastEnvelope(meta.deviceID, stored);
  }

  override async webSocketClose(ws: WebSocket): Promise<void> {
    try {
      ws.close();
    } catch {
      // ignore
    }
  }

  override async webSocketError(ws: WebSocket): Promise<void> {
    try {
      ws.close();
    } catch {
      // ignore
    }
  }

  private async handlePush(request: Request): Promise<Response> {
    let env: Envelope;
    try {
      env = (await request.json()) as Envelope;
    } catch {
      return apiError(400, 'invalid_json', 'invalid json');
    }
    if (!SAFE_ID_REGEX.test(env.groupHash || '') || !SAFE_ID_REGEX.test(env.senderDeviceID || '')) {
      return apiError(400, 'invalid_params', 'invalid groupHash or senderDeviceID');
    }
    const stored = this.appendEnvelope(env);
    this.broadcastEnvelope(env.senderDeviceID, stored);
    return jsonResponse(stored);
  }

  private handleSync(url: URL): Response {
    const since = Number(url.searchParams.get('since') || '0') || 0;
    let limit = Number(url.searchParams.get('limit') || '100') || 100;
    if (limit <= 0 || limit > 200) limit = 100;

    const rows = this.ctx.storage.sql
      .exec<{
        seq: number;
        id: string;
        group_hash: string;
        sender_device_id: string;
        created_at_ms: number;
        ciphertext_base64: string;
        blob_id: string | null;
        blob_size: number | null;
      }>(
        `SELECT seq, id, group_hash, sender_device_id, created_at_ms, ciphertext_base64, blob_id, blob_size
         FROM envelopes WHERE seq > ? ORDER BY seq ASC LIMIT ?`,
        since,
        limit,
      )
      .toArray();

    const envelopes: Envelope[] = rows.map((r) => {
      const out: Envelope = {
        id: r.id,
        seq: r.seq,
        groupHash: r.group_hash,
        senderDeviceID: r.sender_device_id,
        createdAtMs: r.created_at_ms,
        ciphertextBase64: r.ciphertext_base64,
      };
      if (r.blob_id) out.blobID = r.blob_id;
      if (r.blob_size !== null && r.blob_size !== undefined) out.blobSize = r.blob_size;
      return out;
    });
    return jsonResponse(envelopes);
  }

  private async handleBlob(request: Request, url: URL): Promise<Response> {
    const blobID = url.pathname.slice('/v1/blobs/'.length);
    const groupHash = url.searchParams.get('group') || '';
    if (!SAFE_ID_REGEX.test(blobID) || !SAFE_ID_REGEX.test(groupHash)) {
      return apiError(400, 'invalid_params', 'invalid blobID or group');
    }

    const r2Key = `blobs/${groupHash}/${blobID}`;

    if (request.method === 'POST' || request.method === 'PUT') {
      const data = new Uint8Array(await request.arrayBuffer());
      if (data.byteLength > this.maxBlobBytes()) {
        return apiError(413, 'blob_too_large', 'blob exceeds max allowed size');
      }

      if (this.env.BLOBS) {
        await this.env.BLOBS.put(r2Key, data, {
          httpMetadata: { contentType: 'application/octet-stream' },
          customMetadata: { createdAtMs: String(Date.now()) },
        });
        return new Response(null, { status: 201 });
      }

      const now = Date.now();
      this.ctx.storage.sql.exec('DELETE FROM blob_chunks WHERE blob_id = ?', blobID);
      let idx = 0;
      for (let off = 0; off < data.byteLength; off += CHUNK_SIZE_BYTES) {
        const slice = data.subarray(off, Math.min(off + CHUNK_SIZE_BYTES, data.byteLength));
        this.ctx.storage.sql.exec(
          'INSERT INTO blob_chunks (blob_id, chunk_idx, data, created_at_ms) VALUES (?, ?, ?, ?)',
          blobID,
          idx,
          slice,
          now,
        );
        idx += 1;
      }
      await this.scheduleBlobCleanupAlarm();
      return new Response(null, { status: 201 });
    }

    if (request.method === 'GET') {
      if (this.env.BLOBS) {
        const obj = await this.env.BLOBS.get(r2Key) || await this.env.BLOBS.get(`${groupHash}/${blobID}`);
        if (!obj) return apiError(404, 'not_found', 'blob not found');
        return new Response(obj.body, {
          status: 200,
          headers: { 'Content-Type': 'application/octet-stream' },
        });
      }

      const countRow = this.ctx.storage.sql
        .exec<{ cnt: number; total: number }>(
          'SELECT COUNT(*) AS cnt, COALESCE(SUM(LENGTH(data)), 0) AS total FROM blob_chunks WHERE blob_id = ?',
          blobID,
        )
        .one();
      if (!countRow || countRow.cnt === 0) {
        return apiError(404, 'not_found', 'blob not found');
      }
      const sql = this.ctx.storage.sql;
      let idx = 0;
      const totalChunks = Number(countRow.cnt);
      const stream = new ReadableStream<Uint8Array>({
        pull(controller) {
          if (idx >= totalChunks) {
            controller.close();
            return;
          }
          const row = sql
            .exec<{ data: ArrayBuffer }>(
              'SELECT data FROM blob_chunks WHERE blob_id = ? AND chunk_idx = ?',
              blobID,
              idx,
            )
            .toArray()[0];
          idx += 1;
          if (!row) {
            controller.close();
            return;
          }
          controller.enqueue(new Uint8Array(row.data));
        },
      });
      return new Response(stream, {
        status: 200,
        headers: {
          'Content-Type': 'application/octet-stream',
          'Content-Length': String(countRow.total),
        },
      });
    }

    return apiError(405, 'method_not_allowed', 'method not allowed');
  }

  private async scheduleBlobCleanupAlarm(): Promise<void> {
    const existing = await this.ctx.storage.getAlarm();
    if (!existing) {
      await this.ctx.storage.setAlarm(Date.now() + 6 * 60 * 60 * 1000);
    }
  }

  override async alarm(): Promise<void> {
    this.ensureSchema();
    const cutoff = Date.now() - this.blobTTLMs();
    this.ctx.storage.sql.exec('DELETE FROM blob_chunks WHERE created_at_ms < ?', cutoff);
    const remaining = this.ctx.storage.sql
      .exec<{ cnt: number }>('SELECT COUNT(*) AS cnt FROM blob_chunks')
      .one();
    if (remaining.cnt > 0) {
      await this.ctx.storage.setAlarm(Date.now() + 6 * 60 * 60 * 1000);
    }
  }

  private appendEnvelope(env: Envelope): Envelope {
    const now = env.createdAtMs || Date.now();
    this.ctx.storage.sql.exec(
      `INSERT INTO envelopes (id, group_hash, sender_device_id, created_at_ms, ciphertext_base64, blob_id, blob_size)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      env.id || crypto.randomUUID(),
      env.groupHash,
      env.senderDeviceID,
      now,
      env.ciphertextBase64,
      env.blobID ?? null,
      env.blobSize ?? null,
    );
    const seqRow = this.ctx.storage.sql.exec<{ seq: number }>('SELECT last_insert_rowid() AS seq').one();
    const seq = Number(seqRow.seq);

    const maxKeep = this.maxEnvelopes();
    this.ctx.storage.sql.exec(
      `DELETE FROM envelopes WHERE seq <= (
         SELECT seq FROM envelopes ORDER BY seq DESC LIMIT 1 OFFSET ?
       )`,
      maxKeep,
    );

    return {
      ...env,
      seq,
      createdAtMs: now,
    };
  }

  private broadcastEnvelope(senderDeviceID: string, env: Envelope): void {
    const payload = JSON.stringify(env);
    for (const sock of this.ctx.getWebSockets()) {
      const meta = sock.deserializeAttachment() as { deviceID?: string } | null;
      if (meta?.deviceID === senderDeviceID) continue;
      try {
        sock.send(payload);
      } catch {
        try {
          sock.close();
        } catch {
          // ignore
        }
      }
    }
  }
}

// ============================================================================
// 2. SignalingRoomDO — Presence, Zero-Knowledge Group Key Vault & WS Tunnel
// ============================================================================

type SignalingSocketAttachment =
  | {
      kind: 'signal';
      userID: string;
      deviceID: string;
      observedPublicIP: string;
      presence: SignalPeerPresence;
    }
  | {
      kind: 'tunnel';
      userID: string;
      tunnelID: string;
      deviceID: string;
      peerID: string;
      role: 'dial' | 'accept';
    };

export class SignalingRoomDO extends DurableObject<Env> {
  private schemaReady = false;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.ctx.setWebSocketAutoResponse(
      new WebSocketRequestResponsePair('{"type":"ping"}', '{"type":"pong"}'),
    );
  }

  private ensureSchema(): void {
    if (this.schemaReady) return;
    this.ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS room_devices (
        device_id TEXT PRIMARY KEY,
        device_json TEXT NOT NULL,
        updated_at_ms INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS sealed_group_keys (
        target_device_id TEXT PRIMARY KEY,
        envelope_json TEXT NOT NULL,
        key_updated_at_ms INTEGER NOT NULL
      );
    `);
    this.schemaReady = true;
  }

  private upsertRoomDevice(dev: KnownAccountDevice): void {
    if (!SAFE_ID_REGEX.test(dev.deviceID) || !dev.signingPublicKeyBase64) return;
    this.ensureSchema();
    const existingRow = this.ctx.storage.sql
      .exec<{ device_json: string }>(
        'SELECT device_json FROM room_devices WHERE device_id = ?',
        dev.deviceID,
      )
      .toArray()[0];
    let merged = { ...dev, updatedAtMs: Date.now() };
    if (existingRow) {
      try {
        const prev = JSON.parse(existingRow.device_json) as KnownAccountDevice;
        if (!merged.x25519PublicKeyBase64 && prev.x25519PublicKeyBase64) {
          merged.x25519PublicKeyBase64 = prev.x25519PublicKeyBase64;
          merged.x25519SignatureBase64 = prev.x25519SignatureBase64;
        }
        if (merged.accountCert === undefined && prev.accountCert !== undefined) {
          merged.accountCert = prev.accountCert;
        }
      } catch {
        // ignore
      }
    }
    this.ctx.storage.sql.exec(
      'INSERT OR REPLACE INTO room_devices (device_id, device_json, updated_at_ms) VALUES (?, ?, ?)',
      merged.deviceID,
      JSON.stringify(merged),
      merged.updatedAtMs,
    );
    // Bound max retained devices per account room to 32
    this.ctx.storage.sql.exec(`
      DELETE FROM room_devices WHERE device_id NOT IN (
        SELECT device_id FROM room_devices ORDER BY updated_at_ms DESC LIMIT 32
      )
    `);
  }

  override async fetch(request: Request): Promise<Response> {
    this.ensureSchema();
    const url = new URL(request.url);
    const userID = request.headers.get('X-SyncNow-Room-ID') || 'unknown';

    if (url.pathname === '/v1/signal/ws') {
      return this.handleSignalWebSocket(request, url, userID);
    }

    if (url.pathname === '/v1/tunnel/ws') {
      return this.handleTunnelWebSocket(request, url, userID);
    }

    if (url.pathname === '/v1/signal/peers' && request.method === 'GET') {
      const exclude = (url.searchParams.get('excludeDevice') || '').trim();
      return jsonResponse({
        userID,
        peers: this.collectOnlinePeers(exclude),
        timeMs: Date.now(),
      });
    }

    if (url.pathname === '/v1/signal/group-vault') {
      return this.handleGroupVault(request, url, userID);
    }

    return apiError(404, 'not_found', 'Not found');
  }

  private handleSignalWebSocket(request: Request, url: URL, userID: string): Response {
    if (request.headers.get('Upgrade')?.toLowerCase() !== 'websocket') {
      return apiError(426, 'upgrade_required', 'Expected Upgrade: websocket');
    }
    const deviceID = (url.searchParams.get('device') || '').trim();
    if (!SAFE_ID_REGEX.test(deviceID)) {
      return apiError(400, 'invalid_device', 'valid device query parameter is required');
    }

    for (const existing of this.ctx.getWebSockets(`sig:${deviceID}`)) {
      try {
        existing.close(1000, 'Replaced by newer connection');
      } catch {
        // ignore
      }
    }

    const observedIP =
      request.headers.get('cf-connecting-ip') ||
      request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
      '';

    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair) as [WebSocket, WebSocket];
    this.ctx.acceptWebSocket(server, [`sig:${deviceID}`]);

    const initialAttachment: SignalingSocketAttachment = {
      kind: 'signal',
      userID,
      deviceID,
      observedPublicIP: observedIP,
      presence: {
        deviceID,
        deviceName: deviceID,
        platform: 'macOS',
        signingPublicKeyBase64: '',
        lanEndpoints: [],
        observedPublicIP: observedIP || undefined,
        tcpPort: 51820,
        udpPort: 0,
        appVersion: '0.1.0',
        online: true,
        updatedAtMs: Date.now(),
      },
    };
    server.serializeAttachment(initialAttachment);

    const peers = this.collectOnlinePeers(deviceID);
    const snapshot: SignalServerMessage = {
      type: 'peers_snapshot',
      userID,
      peers,
      timeMs: Date.now(),
    };
    server.send(JSON.stringify(snapshot));

    return new Response(null, { status: 101, webSocket: client });
  }

  private handleTunnelWebSocket(request: Request, url: URL, userID: string): Response {
    if (request.headers.get('Upgrade')?.toLowerCase() !== 'websocket') {
      return apiError(426, 'upgrade_required', 'Expected Upgrade: websocket');
    }
    const tunnelID = (url.searchParams.get('tunnel') || '').trim();
    const deviceID = (url.searchParams.get('device') || '').trim();
    const peerID = (url.searchParams.get('peer') || '').trim();
    const role = (url.searchParams.get('role') || '').trim();

    if (
      !SAFE_ID_REGEX.test(tunnelID) ||
      !SAFE_ID_REGEX.test(deviceID) ||
      !SAFE_ID_REGEX.test(peerID) ||
      deviceID === peerID
    ) {
      return apiError(400, 'invalid_params', 'valid tunnel, device, and peer parameters are required');
    }
    if (role !== 'dial' && role !== 'accept') {
      return apiError(400, 'invalid_role', 'role must be dial or accept');
    }

    const myTag = `tun:${tunnelID}:${role}`;
    if (this.ctx.getWebSockets(myTag).length > 0) {
      return apiError(409, 'slot_taken', 'tunnel role already occupied');
    }

    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair) as [WebSocket, WebSocket];
    this.ctx.acceptWebSocket(server, [myTag]);

    const att: SignalingSocketAttachment = {
      kind: 'tunnel',
      userID,
      tunnelID,
      deviceID,
      peerID,
      role,
    };
    server.serializeAttachment(att);

    const partnerTag = `tun:${tunnelID}:${role === 'dial' ? 'accept' : 'dial'}`;
    const partners = this.ctx.getWebSockets(partnerTag);
    if (partners.length > 0) {
      const readyText = JSON.stringify({ type: 'tunnel_ready' });
      try {
        partners[0]!.send(readyText);
        server.send(readyText);
      } catch {
        // ignore
      }
    }

    return new Response(null, { status: 101, webSocket: client });
  }

  private async handleGroupVault(request: Request, url: URL, userID: string): Promise<Response> {
    if (request.method === 'GET') {
      const deviceID = (url.searchParams.get('device') || '').trim();
      if (!SAFE_ID_REGEX.test(deviceID)) {
        return apiError(400, 'invalid_device', 'valid device query parameter is required');
      }
      const devRows = this.ctx.storage.sql
        .exec<{ device_json: string }>('SELECT device_json FROM room_devices ORDER BY device_id ASC')
        .toArray();
      const devices: KnownAccountDevice[] = [];
      for (const r of devRows) {
        try {
          devices.push(JSON.parse(r.device_json) as KnownAccountDevice);
        } catch {
          // ignore
        }
      }
      const envRow = this.ctx.storage.sql
        .exec<{ envelope_json: string }>(
          'SELECT envelope_json FROM sealed_group_keys WHERE target_device_id = ?',
          deviceID,
        )
        .toArray()[0];
      let envelopeForMe: SealedGroupKeyEnvelope | null = null;
      if (envRow) {
        try {
          envelopeForMe = JSON.parse(envRow.envelope_json) as SealedGroupKeyEnvelope;
        } catch {
          // ignore
        }
      }
      return jsonResponse({
        userID,
        devices,
        envelopeForMe,
        timeMs: Date.now(),
      });
    }

    if (request.method === 'PUT' || request.method === 'POST') {
      const body = (await request.json().catch(() => null)) as {
        device?: KnownAccountDevice;
        senderDeviceID?: string;
        envelopes?: SealedGroupKeyEnvelope[];
      } | null;
      if (!body) return apiError(400, 'invalid_json', 'invalid json payload');

      if (body.device && SAFE_ID_REGEX.test(body.device.deviceID)) {
        this.upsertRoomDevice(body.device);
      }
      const senderID = (body.senderDeviceID || body.device?.deviceID || '').trim();
      let notified = 0;

      if (SAFE_ID_REGEX.test(senderID) && Array.isArray(body.envelopes)) {
        const now = Date.now();
        for (const env of body.envelopes) {
          if (
            !SAFE_ID_REGEX.test(env.targetDeviceID) ||
            !env.ciphertextBase64 ||
            !env.ephemeralX25519PubBase64
          ) {
            continue;
          }
          const prev = this.ctx.storage.sql
            .exec<{ key_updated_at_ms: number }>(
              'SELECT key_updated_at_ms FROM sealed_group_keys WHERE target_device_id = ?',
              env.targetDeviceID,
            )
            .toArray()[0];
          if (prev && prev.key_updated_at_ms > (env.keyUpdatedAtMs || 0)) {
            continue;
          }
          const stored: SealedGroupKeyEnvelope = {
            ...env,
            senderDeviceID: senderID,
            createdAtMs: now,
          };
          this.ctx.storage.sql.exec(
            'INSERT OR REPLACE INTO sealed_group_keys (target_device_id, envelope_json, key_updated_at_ms) VALUES (?, ?, ?)',
            env.targetDeviceID,
            JSON.stringify(stored),
            env.keyUpdatedAtMs || now,
          );

          const targetSocks = this.ctx.getWebSockets(`sig:${env.targetDeviceID}`);
          if (targetSocks.length > 0) {
            const wake: SignalServerMessage = {
              type: 'signal',
              userID,
              fromDeviceID: senderID,
              kind: 'group_vault_updated',
              payload: '{}',
              timeMs: now,
            };
            const wakeJSON = JSON.stringify(wake);
            for (const s of targetSocks) {
              try {
                s.send(wakeJSON);
                notified += 1;
              } catch {
                // ignore
              }
            }
          }
        }
      }
      return jsonResponse({ ok: true, notified });
    }

    return apiError(405, 'method_not_allowed', 'method not allowed');
  }

  override async webSocketMessage(ws: WebSocket, message: string | ArrayBuffer): Promise<void> {
    const att = ws.deserializeAttachment() as SignalingSocketAttachment | null;
    if (!att) return;

    // 1. Binary PeerSession Tunnel relay
    if (att.kind === 'tunnel') {
      if (typeof message !== 'string') {
        const partnerRole = att.role === 'dial' ? 'accept' : 'dial';
        const partners = this.ctx.getWebSockets(`tun:${att.tunnelID}:${partnerRole}`);
        for (const p of partners) {
          try {
            p.send(message);
          } catch {
            try {
              p.close();
            } catch {
              // ignore
            }
          }
        }
        return;
      }
      try {
        const ctrl = JSON.parse(message) as { type?: string };
        if (ctrl.type === 'ping') {
          ws.send(JSON.stringify({ type: 'pong', timeMs: Date.now() }));
        }
      } catch {
        // ignore
      }
      return;
    }

    // 2. Standard Same-Account Signaling
    const raw = typeof message === 'string' ? message : new TextDecoder().decode(message);
    let msg: SignalClientMessage;
    try {
      msg = JSON.parse(raw) as SignalClientMessage;
    } catch {
      return;
    }

    if (msg.type === 'register' && msg.presence) {
      const updatedPresence: SignalPeerPresence = {
        ...msg.presence,
        deviceID: att.deviceID,
        observedPublicIP: msg.presence.observedPublicIP || att.observedPublicIP || undefined,
        online: true,
        updatedAtMs: Date.now(),
      };
      ws.serializeAttachment({ ...att, presence: updatedPresence });

      if (updatedPresence.signingPublicKeyBase64) {
        this.upsertRoomDevice({
          deviceID: att.deviceID,
          deviceName: updatedPresence.deviceName,
          platform: updatedPresence.platform,
          signingPublicKeyBase64: updatedPresence.signingPublicKeyBase64,
          x25519PublicKeyBase64: updatedPresence.x25519PublicKeyBase64,
          x25519SignatureBase64: updatedPresence.x25519SignatureBase64,
          accountCert: updatedPresence.accountCert,
          updatedAtMs: Date.now(),
        });
      }

      const upsert: SignalServerMessage = {
        type: 'peer_upsert',
        userID: att.userID,
        peer: updatedPresence,
        timeMs: Date.now(),
      };
      const encoded = JSON.stringify(upsert);
      for (const peerSock of this.ctx.getWebSockets()) {
        if (peerSock === ws) continue;
        const peerAtt = peerSock.deserializeAttachment() as SignalingSocketAttachment | null;
        if (!peerAtt || peerAtt.kind === 'tunnel') continue;
        try {
          peerSock.send(encoded);
        } catch {
          // ignore
        }
      }
      return;
    }

    if (msg.type === 'signal' && msg.targetDeviceID && msg.targetDeviceID !== att.deviceID) {
      const targets = this.ctx.getWebSockets(`sig:${msg.targetDeviceID}`);
      if (targets.length === 0) return;
      const fwd: SignalServerMessage = {
        type: 'signal',
        userID: att.userID,
        fromDeviceID: att.deviceID,
        kind: msg.kind,
        payload: msg.payload,
        timeMs: Date.now(),
      };
      const encoded = JSON.stringify(fwd);
      for (const target of targets) {
        try {
          target.send(encoded);
        } catch {
          // ignore
        }
      }
      return;
    }

    if (msg.type === 'ping') {
      const pong: SignalServerMessage = { type: 'pong', timeMs: Date.now() };
      ws.send(JSON.stringify(pong));
    }
  }

  override async webSocketClose(ws: WebSocket): Promise<void> {
    this.handleSocketEnd(ws);
  }

  override async webSocketError(ws: WebSocket): Promise<void> {
    this.handleSocketEnd(ws);
  }

  private handleSocketEnd(ws: WebSocket): void {
    const att = ws.deserializeAttachment() as SignalingSocketAttachment | null;
    try {
      ws.close();
    } catch {
      // ignore
    }
    if (!att) return;

    if (att.kind === 'tunnel') {
      const partnerRole = att.role === 'dial' ? 'accept' : 'dial';
      for (const p of this.ctx.getWebSockets(`tun:${att.tunnelID}:${partnerRole}`)) {
        try {
          p.close(1000, 'Peer tunnel closed');
        } catch {
          // ignore
        }
      }
      return;
    }

    const hasReplacement = this.ctx
      .getWebSockets(`sig:${att.deviceID}`)
      .some((other) => other !== ws && other.readyState === 1);
    if (hasReplacement) return;

    const offline: SignalServerMessage = {
      type: 'peer_offline',
      userID: att.userID,
      deviceID: att.deviceID,
      timeMs: Date.now(),
    };
    const encoded = JSON.stringify(offline);
    for (const sock of this.ctx.getWebSockets()) {
      if (sock === ws) continue;
      const peerAtt = sock.deserializeAttachment() as SignalingSocketAttachment | null;
      if (!peerAtt || peerAtt.kind === 'tunnel' || peerAtt.deviceID === att.deviceID) continue;
      try {
        sock.send(encoded);
      } catch {
        // ignore
      }
    }
  }

  private collectOnlinePeers(excludeDeviceID: string): SignalPeerPresence[] {
    const out: SignalPeerPresence[] = [];
    for (const sock of this.ctx.getWebSockets()) {
      const att = sock.deserializeAttachment() as SignalingSocketAttachment | null;
      if (!att || att.kind === 'tunnel' || !att.presence?.deviceID) continue;
      if (excludeDeviceID && att.deviceID === excludeDeviceID) continue;
      out.push(att.presence);
    }
    return out;
  }
}

// ============================================================================
// 3. MetaStoreDO — Dynamic Config, Device Tokens & Global Tmp Transfer Quota/GC
// ============================================================================

type TmpRow = {
  transfer_id: string;
  group_hash: string;
  sender_device_id: string;
  storage_backend: 'r2' | 'do_sqlite';
  r2_key: string;
  r2_upload_id: string;
  total_plain_bytes: number;
  total_cipher_bytes: number;
  chunk_plain_bytes: number;
  chunk_cipher_bytes: number;
  total_chunks: number;
  uploaded_parts_json: string;
  acked_devices_json: string;
  status: 'uploading' | 'ready';
  created_at_ms: number;
  expires_at_ms: number;
};

function compareSemVer(a: string, b: string): number {
  const pa = a.replace(/^v/i, '').split('.').map((n) => parseInt(n, 10) || 0);
  const pb = b.replace(/^v/i, '').split('.').map((n) => parseInt(n, 10) || 0);
  const len = Math.max(pa.length, pb.length, 3);
  for (let i = 0; i < len; i += 1) {
    const va = pa[i] ?? 0;
    const vb = pb[i] ?? 0;
    if (va < vb) return -1;
    if (va > vb) return 1;
  }
  return 0;
}

export class MetaStoreDO extends DurableObject<Env> {
  private schemaReady = false;
  private cachedTicketSecret: string | null = null;

  private ensureSchema(): void {
    if (this.schemaReady) return;
    this.ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS device_tokens (
        id TEXT PRIMARY KEY,
        label TEXT NOT NULL,
        token_hash TEXT NOT NULL UNIQUE,
        token_preview TEXT NOT NULL,
        room_id TEXT NOT NULL,
        created_at_ms INTEGER NOT NULL,
        expires_at_ms INTEGER NOT NULL DEFAULT 0,
        last_used_at_ms INTEGER NOT NULL DEFAULT 0
      );
      CREATE TABLE IF NOT EXISTS tmp_transfers (
        transfer_id TEXT PRIMARY KEY,
        group_hash TEXT NOT NULL,
        sender_device_id TEXT NOT NULL,
        storage_backend TEXT NOT NULL,
        r2_key TEXT NOT NULL,
        r2_upload_id TEXT NOT NULL DEFAULT '',
        total_plain_bytes INTEGER NOT NULL,
        total_cipher_bytes INTEGER NOT NULL,
        chunk_plain_bytes INTEGER NOT NULL,
        chunk_cipher_bytes INTEGER NOT NULL,
        total_chunks INTEGER NOT NULL,
        uploaded_parts_json TEXT NOT NULL DEFAULT '{}',
        acked_devices_json TEXT NOT NULL DEFAULT '[]',
        status TEXT NOT NULL,
        created_at_ms INTEGER NOT NULL,
        expires_at_ms INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_tmp_expires ON tmp_transfers(expires_at_ms);
    `);
    this.schemaReady = true;
  }

  private async getTicketSecret(): Promise<string> {
    if (this.cachedTicketSecret) return this.cachedTicketSecret;
    let secret = await this.ctx.storage.get<string>('tmp_ticket_secret');
    if (!secret || secret.length < 32) {
      secret = randomHex(32);
      await this.ctx.storage.put('tmp_ticket_secret', secret);
    }
    this.cachedTicketSecret = secret;
    return secret;
  }

  private async deletePhysicalTmpRow(row: TmpRow): Promise<void> {
    if (row.storage_backend === 'r2' && this.env.BLOBS) {
      if (row.status === 'uploading' && row.r2_upload_id) {
        try {
          await this.env.BLOBS.resumeMultipartUpload(row.r2_key, row.r2_upload_id).abort();
        } catch {
          // ignore
        }
      }
      try {
        await this.env.BLOBS.delete(row.r2_key);
      } catch {
        // ignore
      }
    } else if (row.storage_backend === 'do_sqlite') {
      try {
        const stub = this.env.RELAY_GROUP.get(this.env.RELAY_GROUP.idFromName(row.group_hash));
        await stub.fetch(`https://internal/internal/do-tmp/${row.transfer_id}`, { method: 'DELETE' });
      } catch {
        // ignore
      }
    }
    this.ctx.storage.sql.exec('DELETE FROM tmp_transfers WHERE transfer_id = ?', row.transfer_id);
  }

  private usedTmpBytes(): number {
    const r = this.ctx.storage.sql
      .exec<{ total: number }>('SELECT COALESCE(SUM(total_cipher_bytes), 0) AS total FROM tmp_transfers')
      .one();
    return Number(r.total || 0);
  }

  private async sweepExpiredTmp(): Promise<void> {
    const now = Date.now();
    const staleUploadCutoff = now - 60 * 60 * 1000;
    const expired = this.ctx.storage.sql
      .exec<TmpRow>(
        `SELECT * FROM tmp_transfers
         WHERE expires_at_ms <= ? OR (status = 'uploading' AND created_at_ms < ?)`,
        now,
        staleUploadCutoff,
      )
      .toArray();
    for (const row of expired) {
      await this.deletePhysicalTmpRow(row);
    }
  }

  private async evictForSpace(neededBytes: number, maxTotalBytes: number): Promise<void> {
    await this.sweepExpiredTmp();
    if (this.usedTmpBytes() + neededBytes <= maxTotalBytes) return;

    const candidates = this.ctx.storage.sql
      .exec<TmpRow>(`SELECT * FROM tmp_transfers WHERE status = 'ready' ORDER BY expires_at_ms ASC`)
      .toArray();

    // Prioritize deleting already-ACKed transfers first, then earliest expiring
    candidates.sort((a, b) => {
      const ackA = a.acked_devices_json !== '[]' ? 0 : 1;
      const ackB = b.acked_devices_json !== '[]' ? 0 : 1;
      if (ackA !== ackB) return ackA - ackB;
      return a.expires_at_ms - b.expires_at_ms;
    });

    for (const cand of candidates) {
      if (this.usedTmpBytes() + neededBytes <= maxTotalBytes) break;
      await this.deletePhysicalTmpRow(cand);
    }
  }

  private async scheduleCleanupAlarm(): Promise<void> {
    const cur = await this.ctx.storage.getAlarm();
    if (!cur) {
      await this.ctx.storage.setAlarm(Date.now() + 30 * 60 * 1000);
    }
  }

  override async alarm(): Promise<void> {
    this.ensureSchema();
    await this.sweepExpiredTmp();
    const remaining = this.ctx.storage.sql
      .exec<{ cnt: number }>('SELECT COUNT(*) AS cnt FROM tmp_transfers')
      .one();
    if (Number(remaining.cnt) > 0) {
      await this.ctx.storage.setAlarm(Date.now() + 30 * 60 * 1000);
    }
  }

  private buildTmpStats(cfg: DynamicRelayConfig): TmpStatsSummary {
    const rows = this.ctx.storage.sql
      .exec<{ status: string; total_cipher_bytes: number }>(
        'SELECT status, total_cipher_bytes FROM tmp_transfers',
      )
      .toArray();
    let activeFiles = 0;
    let uploadingFiles = 0;
    let usedBytes = 0;
    for (const r of rows) {
      usedBytes += Number(r.total_cipher_bytes || 0);
      if (r.status === 'ready') activeFiles += 1;
      else uploadingFiles += 1;
    }
    return {
      storageBackend: this.env.BLOBS ? 'r2' : 'do_sqlite',
      activeFiles,
      uploadingFiles,
      usedBytes,
      maxTmpFileMB: cfg.maxTmpFileMB,
      maxTmpTotalMB: cfg.maxTmpTotalMB,
      tmpTTLHours: cfg.tmpTTLHours,
      tmpAckGraceMinutes: cfg.tmpAckGraceMinutes,
    };
  }

  private listPublicDeviceTokens(): DeviceTokenRecord[] {
    const rows = this.ctx.storage.sql
      .exec<{
        id: string;
        label: string;
        token_preview: string;
        room_id: string;
        created_at_ms: number;
        expires_at_ms: number;
        last_used_at_ms: number;
      }>(
        `SELECT id, label, token_preview, room_id, created_at_ms, expires_at_ms, last_used_at_ms
         FROM device_tokens ORDER BY created_at_ms DESC`,
      )
      .toArray();
    return rows.map((r) => ({
      id: r.id,
      label: r.label,
      tokenPreview: r.token_preview,
      roomID: r.room_id,
      createdAtMs: r.created_at_ms,
      expiresAtMs: r.expires_at_ms || undefined,
      lastUsedAtMs: r.last_used_at_ms || undefined,
    }));
  }

  override async fetch(request: Request): Promise<Response> {
    this.ensureSchema();
    const url = new URL(request.url);
    const path = url.pathname;

    if (path === '/internal/ticket-secret') {
      return jsonResponse({ secretHex: await this.getTicketSecret() });
    }

    if (path === '/internal/config') {
      if (request.method === 'GET') {
        const cfg = await this.ctx.storage.get<DynamicRelayConfig>('relay_config');
        return jsonResponse(cfg ?? null);
      }
      if (request.method === 'PUT') {
        const cfg = (await request.json()) as DynamicRelayConfig;
        await this.ctx.storage.put('relay_config', cfg);
        return jsonResponse({ ok: true });
      }
      if (request.method === 'DELETE') {
        await this.ctx.storage.delete('relay_config');
        this.ctx.storage.sql.exec('DELETE FROM device_tokens');
        return jsonResponse({ ok: true });
      }
    }

    if (path === '/internal/admin-summary' && request.method === 'POST') {
      const cfg = (await request.json()) as DynamicRelayConfig;
      await this.sweepExpiredTmp();
      return jsonResponse({
        tmpStats: this.buildTmpStats(cfg),
        deviceTokens: this.listPublicDeviceTokens(),
      });
    }

    if (path === '/internal/purge-tmp' && request.method === 'POST') {
      const cfg = (await request.json()) as DynamicRelayConfig;
      const all = this.ctx.storage.sql.exec<TmpRow>('SELECT * FROM tmp_transfers').toArray();
      let freedBytes = 0;
      for (const row of all) {
        freedBytes += Number(row.total_cipher_bytes || 0);
        await this.deletePhysicalTmpRow(row);
      }
      return jsonResponse({
        ok: true,
        purgedCount: all.length,
        freedBytes,
        tmpStats: this.buildTmpStats(cfg),
      });
    }

    // Device token internal & external management
    if (path === '/internal/device-tokens/verify' && request.method === 'POST') {
      const { tokenHash } = (await request.json()) as { tokenHash: string };
      const row = this.ctx.storage.sql
        .exec<{ id: string; room_id: string; expires_at_ms: number; last_used_at_ms: number }>(
          'SELECT id, room_id, expires_at_ms, last_used_at_ms FROM device_tokens WHERE token_hash = ?',
          tokenHash,
        )
        .toArray()[0];
      const now = Date.now();
      if (!row || (row.expires_at_ms > 0 && now >= row.expires_at_ms)) {
        return jsonResponse({ valid: false });
      }
      if (now - row.last_used_at_ms > 60_000) {
        this.ctx.storage.sql.exec(
          'UPDATE device_tokens SET last_used_at_ms = ? WHERE id = ?',
          now,
          row.id,
        );
      }
      return jsonResponse({ valid: true, record: { id: row.id, roomID: row.room_id } });
    }

    if (path === '/internal/device-tokens' && request.method === 'GET') {
      return jsonResponse({ tokens: this.listPublicDeviceTokens() });
    }

    if (path === '/internal/device-tokens/issue' && request.method === 'POST') {
      const { label, roomID, ttlDays } = (await request.json()) as {
        label?: string;
        roomID: string;
        ttlDays?: number;
      };
      const rawToken = DEVICE_TOKEN_PREFIX + randomHex(24);
      const tokenHash = await sha256Hex(rawToken);
      const id = 'dt_' + randomHex(8);
      const now = Date.now();
      const exp = ttlDays && ttlDays > 0 ? now + ttlDays * 24 * 60 * 60 * 1000 : 0;
      const preview = `${rawToken.slice(0, 14)}…${rawToken.slice(-4)}`;
      const cleanLabel = (label || 'Mobile / QR Device').trim() || 'Mobile / QR Device';

      this.ctx.storage.sql.exec(
        `INSERT INTO device_tokens (id, label, token_hash, token_preview, room_id, created_at_ms, expires_at_ms, last_used_at_ms)
         VALUES (?, ?, ?, ?, ?, ?, ?, 0)`,
        id,
        cleanLabel,
        tokenHash,
        preview,
        roomID || 'static-owner',
        now,
        exp,
      );
      this.ctx.storage.sql.exec(`
        DELETE FROM device_tokens WHERE id NOT IN (
          SELECT id FROM device_tokens ORDER BY created_at_ms DESC LIMIT 64
        )
      `);
      return jsonResponse({
        token: rawToken,
        record: {
          id,
          label: cleanLabel,
          tokenPreview: preview,
          roomID: roomID || 'static-owner',
          createdAtMs: now,
          expiresAtMs: exp || undefined,
        },
      });
    }

    if (path.startsWith('/internal/device-tokens/') && request.method === 'DELETE') {
      const id = path.slice('/internal/device-tokens/'.length);
      this.ctx.storage.sql.exec('DELETE FROM device_tokens WHERE id = ?', id);
      return jsonResponse({ ok: true });
    }

    // Tmp transfer control-plane operations
    if (path === '/internal/tmp/init' && request.method === 'POST') {
      const body = (await request.json()) as {
        transferID: string;
        groupHash: string;
        senderDeviceID: string;
        totalPlainBytes: number;
        totalCipherBytes: number;
        chunkPlainBytes?: number;
        totalChunks: number;
        ttlHours?: number;
        cfg: DynamicRelayConfig;
      };
      const chunkPlain = body.chunkPlainBytes || DEFAULT_TMP_CHUNK_PLAIN_BYTES;
      if (chunkPlain < 64 * 1024 || chunkPlain > 32 * 1024 * 1024) {
        return apiError(400, 'invalid_chunk_size', 'chunkPlainBytes must be between 64KB and 32MB');
      }
      const expectedChunks = Math.ceil(body.totalPlainBytes / chunkPlain);
      if (
        body.totalPlainBytes <= 0 ||
        body.totalChunks <= 0 ||
        body.totalChunks !== expectedChunks ||
        body.totalChunks > MAX_TMP_CHUNKS_PER_TRANSFER
      ) {
        return apiError(400, 'invalid_chunks', 'invalid totalPlainBytes or totalChunks');
      }
      const expectedCipher = body.totalPlainBytes + body.totalChunks * TMP_CHUNK_AEAD_TAG_BYTES;
      if (body.totalCipherBytes !== expectedCipher) {
        return apiError(400, 'invalid_cipher_size', 'totalCipherBytes mismatch');
      }

      const maxFileBytes = body.cfg.maxTmpFileMB * 1024 * 1024;
      if (body.totalCipherBytes > maxFileBytes) {
        return apiError(
          413,
          'file_too_large',
          `file exceeds maxTmpFileMB (${body.cfg.maxTmpFileMB} MB)`,
        );
      }

      const now = Date.now();
      const existing = this.ctx.storage.sql
        .exec<TmpRow>('SELECT * FROM tmp_transfers WHERE transfer_id = ?', body.transferID)
        .toArray()[0];
      const secret = await this.getTicketSecret();

      if (existing && existing.group_hash === body.groupHash && now < existing.expires_at_ms) {
        const partsMap = JSON.parse(existing.uploaded_parts_json || '{}') as Record<string, string>;
        const uploadedChunks = Object.keys(partsMap)
          .map((k) => Number(k))
          .sort((a, b) => a - b);
        const ticket = await signTmpTicket(secret, {
          tid: existing.transfer_id,
          grp: existing.group_hash,
          backend: existing.storage_backend,
          r2Key: existing.r2_key,
          uploadId: existing.r2_upload_id || undefined,
          chunkCipher: existing.chunk_cipher_bytes,
          totalCipher: existing.total_cipher_bytes,
          totalChunks: existing.total_chunks,
          exp: existing.expires_at_ms,
        });
        return jsonResponse({
          transferID: existing.transfer_id,
          storageBackend: existing.storage_backend,
          chunkPlainBytes: existing.chunk_plain_bytes,
          chunkCipherBytes: existing.chunk_cipher_bytes,
          totalChunks: existing.total_chunks,
          expiresAtMs: existing.expires_at_ms,
          ticket,
          uploadedChunks,
          status: existing.status,
        });
      }

      const maxTotalBytes = body.cfg.maxTmpTotalMB * 1024 * 1024;
      await this.evictForSpace(body.totalCipherBytes, maxTotalBytes);
      if (this.usedTmpBytes() + body.totalCipherBytes > maxTotalBytes) {
        return apiError(
          507,
          'quota_exceeded',
          `relay tmp storage full (limit ${body.cfg.maxTmpTotalMB} MB)`,
        );
      }

      const backend: 'r2' | 'do_sqlite' = this.env.BLOBS ? 'r2' : 'do_sqlite';
      const r2Key = `tmp/${body.groupHash}/${body.transferID}`;
      let r2UploadID = '';
      if (backend === 'r2' && this.env.BLOBS && body.totalChunks > 1) {
        const mpu = await this.env.BLOBS.createMultipartUpload(r2Key, {
          httpMetadata: { contentType: 'application/octet-stream' },
          customMetadata: {
            groupHash: body.groupHash,
            createdAtMs: String(now),
          },
        });
        r2UploadID = mpu.uploadId;
      }

      const ttlHours =
        body.ttlHours && body.ttlHours > 0 && body.ttlHours < body.cfg.tmpTTLHours
          ? body.ttlHours
          : body.cfg.tmpTTLHours;
      const expiresAtMs = now + ttlHours * 60 * 60 * 1000;
      const chunkCipher = chunkPlain + TMP_CHUNK_AEAD_TAG_BYTES;

      this.ctx.storage.sql.exec(
        `INSERT OR REPLACE INTO tmp_transfers (
          transfer_id, group_hash, sender_device_id, storage_backend, r2_key, r2_upload_id,
          total_plain_bytes, total_cipher_bytes, chunk_plain_bytes, chunk_cipher_bytes,
          total_chunks, uploaded_parts_json, acked_devices_json, status, created_at_ms, expires_at_ms
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '{}', '[]', 'uploading', ?, ?)`,
        body.transferID,
        body.groupHash,
        body.senderDeviceID || '',
        backend,
        r2Key,
        r2UploadID,
        body.totalPlainBytes,
        body.totalCipherBytes,
        chunkPlain,
        chunkCipher,
        body.totalChunks,
        now,
        expiresAtMs,
      );
      await this.scheduleCleanupAlarm();

      const ticket = await signTmpTicket(secret, {
        tid: body.transferID,
        grp: body.groupHash,
        backend,
        r2Key,
        uploadId: r2UploadID || undefined,
        chunkCipher,
        totalCipher: body.totalCipherBytes,
        totalChunks: body.totalChunks,
        exp: expiresAtMs,
      });

      return jsonResponse({
        transferID: body.transferID,
        storageBackend: backend,
        chunkPlainBytes: chunkPlain,
        chunkCipherBytes: chunkCipher,
        totalChunks: body.totalChunks,
        expiresAtMs,
        ticket,
        uploadedChunks: [],
        status: 'uploading',
      });
    }

    if (path === '/internal/tmp/record-part' && request.method === 'POST') {
      const { transferID, partIndex, etag } = (await request.json()) as {
        transferID: string;
        partIndex: number;
        etag: string;
      };
      const row = this.ctx.storage.sql
        .exec<TmpRow>('SELECT * FROM tmp_transfers WHERE transfer_id = ?', transferID)
        .toArray()[0];
      if (!row) return apiError(404, 'not_found', 'transfer not found');
      const map = JSON.parse(row.uploaded_parts_json || '{}') as Record<string, string>;
      map[String(partIndex)] = etag;
      this.ctx.storage.sql.exec(
        'UPDATE tmp_transfers SET uploaded_parts_json = ? WHERE transfer_id = ?',
        JSON.stringify(map),
        transferID,
      );
      return jsonResponse({ ok: true });
    }

    if (path === '/internal/tmp/complete' && request.method === 'POST') {
      const { transferID, groupHash, parts } = (await request.json()) as {
        transferID: string;
        groupHash?: string;
        parts?: { partNumber: number; etag: string }[];
      };
      const row = this.ctx.storage.sql
        .exec<TmpRow>('SELECT * FROM tmp_transfers WHERE transfer_id = ?', transferID)
        .toArray()[0];
      if (!row || (groupHash && row.group_hash !== groupHash)) {
        return apiError(404, 'not_found', 'transfer not found');
      }
      const secret = await this.getTicketSecret();
      const ticket = await signTmpTicket(secret, {
        tid: row.transfer_id,
        grp: row.group_hash,
        backend: row.storage_backend,
        r2Key: row.r2_key,
        chunkCipher: row.chunk_cipher_bytes,
        totalCipher: row.total_cipher_bytes,
        totalChunks: row.total_chunks,
        exp: row.expires_at_ms,
      });

      if (row.status === 'ready') {
        return jsonResponse({ ok: true, transferID, expiresAtMs: row.expires_at_ms, ticket });
      }

      if (row.storage_backend === 'r2' && this.env.BLOBS && row.total_chunks > 1) {
        const uploadedList =
          parts && parts.length === row.total_chunks
            ? parts
            : Object.entries(JSON.parse(row.uploaded_parts_json || '{}') as Record<string, string>).map(
                ([idx, etag]) => ({ partNumber: Number(idx) + 1, etag }),
              );
        if (uploadedList.length < row.total_chunks) {
          return apiError(400, 'incomplete_parts', 'missing uploaded parts');
        }
        uploadedList.sort((a, b) => a.partNumber - b.partNumber);
        const mpu = this.env.BLOBS.resumeMultipartUpload(row.r2_key, row.r2_upload_id);
        await mpu.complete(uploadedList);
      } else if (row.storage_backend === 'do_sqlite') {
        const map = JSON.parse(row.uploaded_parts_json || '{}') as Record<string, string>;
        if (Object.keys(map).length < row.total_chunks) {
          return apiError(400, 'incomplete_parts', 'missing uploaded parts');
        }
      }

      this.ctx.storage.sql.exec(
        `UPDATE tmp_transfers SET status = 'ready', r2_upload_id = '' WHERE transfer_id = ?`,
        transferID,
      );
      return jsonResponse({ ok: true, transferID, expiresAtMs: row.expires_at_ms, ticket });
    }

    if (path.startsWith('/internal/tmp/lookup/') && request.method === 'GET') {
      const transferID = path.slice('/internal/tmp/lookup/'.length);
      const groupHash = (url.searchParams.get('group') || '').trim();
      const row = this.ctx.storage.sql
        .exec<TmpRow>('SELECT * FROM tmp_transfers WHERE transfer_id = ?', transferID)
        .toArray()[0];
      if (
        !row ||
        row.status !== 'ready' ||
        Date.now() >= row.expires_at_ms ||
        (groupHash && row.group_hash !== groupHash)
      ) {
        return apiError(404, 'not_found', 'tmp blob not found or expired');
      }
      return jsonResponse({
        tid: row.transfer_id,
        grp: row.group_hash,
        backend: row.storage_backend,
        r2Key: row.r2_key,
        chunkCipher: row.chunk_cipher_bytes,
        totalCipher: row.total_cipher_bytes,
        totalChunks: row.total_chunks,
        exp: row.expires_at_ms,
      });
    }

    if (path === '/internal/tmp/ack' && request.method === 'POST') {
      const { transferID, groupHash, deviceID, ackGraceMinutes } = (await request.json()) as {
        transferID: string;
        groupHash?: string;
        deviceID?: string;
        ackGraceMinutes: number;
      };
      const row = this.ctx.storage.sql
        .exec<TmpRow>('SELECT * FROM tmp_transfers WHERE transfer_id = ?', transferID)
        .toArray()[0];
      if (!row || (groupHash && row.group_hash !== groupHash)) {
        return jsonResponse({ ok: true, deleted: true });
      }
      const acked = new Set<string>(JSON.parse(row.acked_devices_json || '[]') as string[]);
      if (deviceID) acked.add(deviceID);

      if (ackGraceMinutes === 0) {
        await this.deletePhysicalTmpRow(row);
        return jsonResponse({ ok: true, deleted: true, expiresAtMs: 0 });
      }
      let nextExp = row.expires_at_ms;
      if (ackGraceMinutes > 0) {
        nextExp = Math.min(nextExp, Date.now() + ackGraceMinutes * 60 * 1000);
      }
      this.ctx.storage.sql.exec(
        'UPDATE tmp_transfers SET acked_devices_json = ?, expires_at_ms = ? WHERE transfer_id = ?',
        JSON.stringify(Array.from(acked)),
        nextExp,
        transferID,
      );
      return jsonResponse({ ok: true, deleted: false, expiresAtMs: nextExp });
    }

    if (path.startsWith('/internal/tmp/') && request.method === 'DELETE') {
      const transferID = path.slice('/internal/tmp/'.length);
      const groupHash = (url.searchParams.get('group') || '').trim();
      const row = this.ctx.storage.sql
        .exec<TmpRow>('SELECT * FROM tmp_transfers WHERE transfer_id = ?', transferID)
        .toArray()[0];
      let deleted = false;
      if (row && (!groupHash || row.group_hash === groupHash)) {
        await this.deletePhysicalTmpRow(row);
        deleted = true;
      }
      return jsonResponse({ ok: true, deleted });
    }

    // Legacy release manifest check (preserved for test suite compatibility)
    if (path === '/v1/updates/check' && request.method === 'GET') {
      const platform = (url.searchParams.get('platform') || 'macos').toLowerCase();
      const arch = (url.searchParams.get('arch') || 'arm64').toLowerCase();
      const channel = (url.searchParams.get('channel') || 'stable').toLowerCase();
      const curVersion = url.searchParams.get('version') || '0.0.0';
      const curBuild = Number(url.searchParams.get('build') || '0') || 0;

      const releases = (await this.ctx.storage.get<ReleaseEntry[]>('releases')) || [];
      const match =
        releases.find(
          (r) =>
            r.platform.toLowerCase() === platform &&
            r.channel.toLowerCase() === channel &&
            (r.arch.toLowerCase() === arch || r.arch.toLowerCase() === 'universal'),
        ) || null;

      if (!match) {
        return jsonResponse({
          hasUpdate: false,
          forceUpdate: false,
          currentVersion: curVersion,
          currentBuild: curBuild,
          latestVersion: curVersion,
          latestBuild: curBuild,
          minRequiredVersion: curVersion,
          minRequiredBuild: curBuild,
          downloadURL: '',
          sha256: '',
          fileSizeBytes: 0,
          releaseNotes: {},
          publishedAtMs: 0,
        });
      }

      const cmpLatest = compareSemVer(curVersion, match.latestVersion);
      const hasUpdate = cmpLatest < 0 || (cmpLatest === 0 && curBuild < match.latestBuild);
      const cmpMin = match.minRequiredVersion ? compareSemVer(curVersion, match.minRequiredVersion) : 0;
      const belowMin =
        (match.minRequiredVersion && cmpMin < 0) ||
        (match.minRequiredVersion &&
          cmpMin === 0 &&
          match.minRequiredBuild > 0 &&
          curBuild < match.minRequiredBuild);
      const forceUpdate = Boolean(hasUpdate && (match.forceUpdate || belowMin));

      return jsonResponse({
        hasUpdate,
        forceUpdate,
        currentVersion: curVersion,
        currentBuild: curBuild,
        latestVersion: match.latestVersion,
        latestBuild: match.latestBuild,
        minRequiredVersion: match.minRequiredVersion || '',
        minRequiredBuild: match.minRequiredBuild || 0,
        downloadURL: match.downloadURL,
        sha256: match.sha256,
        ed25519Signature: match.ed25519Signature,
        fileSizeBytes: match.fileSizeBytes,
        releaseNotes: match.releaseNotes || {},
        publishedAtMs: match.publishedAtMs || 0,
      });
    }

    if (path === '/v1/admin/updates' && (request.method === 'POST' || request.method === 'PUT')) {
      let entry: ReleaseEntry;
      try {
        entry = (await request.json()) as ReleaseEntry;
      } catch {
        return apiError(400, 'invalid_json', 'invalid release entry json');
      }
      if (!entry.platform || !entry.latestVersion) {
        return apiError(400, 'invalid_params', 'platform and latestVersion are required');
      }
      entry.channel = entry.channel || 'stable';
      entry.arch = entry.arch || 'universal';
      entry.publishedAtMs = entry.publishedAtMs || Date.now();

      const releases = (await this.ctx.storage.get<ReleaseEntry[]>('releases')) || [];
      const idx = releases.findIndex(
        (r) =>
          r.platform === entry.platform &&
          r.arch === entry.arch &&
          r.channel === entry.channel,
      );
      if (idx >= 0) releases[idx] = entry;
      else releases.push(entry);
      await this.ctx.storage.put('releases', releases);
      return jsonResponse({ ok: true, release: entry });
    }

    return apiError(404, 'not_found', 'Not found');
  }
}
