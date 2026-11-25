import { DurableObject } from 'cloudflare:workers';
import {
  apiError,
  jsonResponse,
  SAFE_ID_REGEX,
  type DynamicRelayConfig,
  type Env,
  type Envelope,
  type ReleaseEntry,
  type SignalClientMessage,
  type SignalPeerPresence,
  type SignalServerMessage,
} from './types.ts';

const CHUNK_SIZE_BYTES = 1024 * 1024; // 1 MiB SQLite chunk fallback when R2 is not bound

// ============================================================================
// 1. RelayGroupDO — E2EE Clipboard Envelopes (/ws, /v1/push, /v1/sync) + Blobs
// ============================================================================

export class RelayGroupDO extends DurableObject<Env> {
  private initialized = false;
  private dynMaxEnvelopes: number | null = null;
  private dynMaxBlobMB: number | null = null;
  private dynBlobTTLDays: number | null = null;

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
      CREATE TABLE IF NOT EXISTS group_meta (
        key TEXT PRIMARY KEY,
        val TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_blob_chunks_created ON blob_chunks(created_at_ms);
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

  private handleWebSocket(request: Request, url: URL): Response {
    if (request.headers.get('Upgrade')?.toLowerCase() !== 'websocket') {
      return apiError(426, 'upgrade_required', 'Expected Upgrade: websocket');
    }
    const groupHash = url.searchParams.get('group') || '';
    const deviceID = url.searchParams.get('device') || '';
    if (!SAFE_ID_REGEX.test(groupHash) || !SAFE_ID_REGEX.test(deviceID)) {
      return apiError(400, 'invalid_params', 'invalid group or device');
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
    let env: Envelope;
    try {
      env = JSON.parse(rawText) as Envelope;
    } catch {
      return;
    }
    if (env.groupHash !== meta.groupHash) return;
    env.senderDeviceID = meta.deviceID;
    const stored = this.appendEnvelope(env);
    this.broadcastEnvelope(meta.deviceID, stored);
  }

  override async webSocketClose(ws: WebSocket): Promise<void> {
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

    const r2Key = `${groupHash}/${blobID}`;

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

      // Free-tier SQLite chunk fallback (no R2 bucket needed!)
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
        const obj = await this.env.BLOBS.get(r2Key);
        if (!obj) return apiError(404, 'not_found', 'blob not found');
        return new Response(obj.body, {
          status: 200,
          headers: { 'Content-Type': 'application/octet-stream' },
        });
      }

      const rows = this.ctx.storage.sql
        .exec<{ data: ArrayBuffer }>(
          'SELECT data FROM blob_chunks WHERE blob_id = ? ORDER BY chunk_idx ASC',
          blobID,
        )
        .toArray();
      if (rows.length === 0) {
        return apiError(404, 'not_found', 'blob not found');
      }
      let total = 0;
      for (const r of rows) total += r.data.byteLength;
      const merged = new Uint8Array(total);
      let offset = 0;
      for (const r of rows) {
        merged.set(new Uint8Array(r.data), offset);
        offset += r.data.byteLength;
      }
      return new Response(merged, {
        status: 200,
        headers: { 'Content-Type': 'application/octet-stream' },
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

    // Retain at most maxEnvelopes
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
// 2. SignalingRoomDO — Same-Account Peer Presence & Matching (/v1/signal/*)
// ============================================================================

interface SignalingAttachment {
  userID: string;
  deviceID: string;
  observedPublicIP: string;
  presence: SignalPeerPresence;
}

export class SignalingRoomDO extends DurableObject<Env> {
  override async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const userID = request.headers.get('X-SyncNow-Room-ID') || 'unknown';

    if (url.pathname === '/v1/signal/ws') {
      if (request.headers.get('Upgrade')?.toLowerCase() !== 'websocket') {
        return apiError(426, 'upgrade_required', 'Expected Upgrade: websocket');
      }
      const deviceID = (url.searchParams.get('device') || '').trim();
      if (!SAFE_ID_REGEX.test(deviceID)) {
        return apiError(400, 'invalid_device', 'valid device query parameter is required');
      }

      // Close any stale socket for the exact same deviceID
      for (const existing of this.ctx.getWebSockets(deviceID)) {
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
      this.ctx.acceptWebSocket(server, [deviceID]);

      const initialAttachment: SignalingAttachment = {
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

      // Immediately push snapshot of all other online devices in the SAME xtags account
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

    if (url.pathname === '/v1/signal/peers' && request.method === 'GET') {
      const exclude = (url.searchParams.get('excludeDevice') || '').trim();
      return jsonResponse({
        userID,
        peers: this.collectOnlinePeers(exclude),
        timeMs: Date.now(),
      });
    }

    return apiError(404, 'not_found', 'Not found');
  }

  override async webSocketMessage(ws: WebSocket, message: string | ArrayBuffer): Promise<void> {
    const att = ws.deserializeAttachment() as SignalingAttachment | null;
    if (!att) return;

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

      const upsert: SignalServerMessage = {
        type: 'peer_upsert',
        userID: att.userID,
        peer: updatedPresence,
        timeMs: Date.now(),
      };
      const encoded = JSON.stringify(upsert);
      for (const peerSock of this.ctx.getWebSockets()) {
        if (peerSock === ws) continue;
        try {
          peerSock.send(encoded);
        } catch {
          // ignore
        }
      }
      return;
    }

    if (msg.type === 'signal' && msg.targetDeviceID && msg.targetDeviceID !== att.deviceID) {
      const targets = this.ctx.getWebSockets(msg.targetDeviceID);
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
    this.broadcastOffline(ws);
  }

  override async webSocketError(ws: WebSocket): Promise<void> {
    this.broadcastOffline(ws);
  }

  private broadcastOffline(ws: WebSocket): void {
    const att = ws.deserializeAttachment() as SignalingAttachment | null;
    try {
      ws.close();
    } catch {
      // ignore
    }
    if (!att) return;
    const offline: SignalServerMessage = {
      type: 'peer_offline',
      userID: att.userID,
      deviceID: att.deviceID,
      timeMs: Date.now(),
    };
    const encoded = JSON.stringify(offline);
    for (const sock of this.ctx.getWebSockets()) {
      if (sock === ws) continue;
      const peerAtt = sock.deserializeAttachment() as SignalingAttachment | null;
      if (peerAtt?.deviceID === att.deviceID) continue;
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
      const att = sock.deserializeAttachment() as SignalingAttachment | null;
      if (!att || !att.presence?.deviceID) continue;
      if (excludeDeviceID && att.deviceID === excludeDeviceID) continue;
      out.push(att.presence);
    }
    return out;
  }
}

// ============================================================================
// 3. MetaStoreDO — Auto-Update & Force-Update Manifest (/v1/updates/*)
// ============================================================================

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
  override async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    // Internal persisted Web Setup dynamic config store
    if (url.pathname === '/internal/config') {
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
        return jsonResponse({ ok: true });
      }
    }

    if (url.pathname === '/v1/updates/check' && request.method === 'GET') {
      const platform = (url.searchParams.get('platform') || 'macos').toLowerCase();
      const arch = (url.searchParams.get('arch') || 'arm64').toLowerCase();
      const channel = (url.searchParams.get('channel') || 'stable').toLowerCase();
      const curVersion = url.searchParams.get('version') || '0.0.0';
      const curBuild = Number(url.searchParams.get('build') || '0') || 0;

      const releases = ((await this.ctx.storage.get<ReleaseEntry[]>('releases')) || []);
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
        (match.minRequiredVersion && cmpMin === 0 && match.minRequiredBuild > 0 && curBuild < match.minRequiredBuild);
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

    if (url.pathname === '/v1/admin/updates' && (request.method === 'POST' || request.method === 'PUT')) {
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

      const releases = ((await this.ctx.storage.get<ReleaseEntry[]>('releases')) || []);
      const idx = releases.findIndex(
        (r) => r.platform === entry.platform && r.arch === entry.arch && r.channel === entry.channel,
      );
      if (idx >= 0) {
        releases[idx] = entry;
      } else {
        releases.push(entry);
      }
      await this.ctx.storage.put('releases', releases);
      return jsonResponse({ ok: true, release: entry });
    }

    return apiError(404, 'not_found', 'Not found');
  }
}
