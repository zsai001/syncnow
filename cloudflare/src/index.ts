import {
  authenticateRequest,
  constantTimeEqual,
  extractBearerToken,
  invalidateConfigCache,
  invalidateDeviceTokenCache,
  isSetupAdmin,
  loadRuntimeConfig,
  verifyOrExchangeXTags,
  verifyTmpTicket,
} from './auth.ts';
import { SETUP_UI_HTML } from './setup_ui.ts';
import {
  apiError,
  DEFAULT_TMP_CHUNK_PLAIN_BYTES,
  jsonResponse,
  MAX_TMP_CHUNKS_PER_TRANSFER,
  RELAY_VERSION,
  SAFE_ID_REGEX,
  type DeviceTokenRecord,
  type DynamicRelayConfig,
  type Env,
  type TmpStatsSummary,
  type TmpTicketClaims,
} from './types.ts';

export { MetaStoreDO, RelayGroupDO, SignalingRoomDO } from './objects.ts';

function withCORS(request: Request, response: Response): Response {
  const origin = request.headers.get('Origin');
  if (!origin || response.status === 101) return response;
  const headers = new Headers(response.headers);
  headers.set('Access-Control-Allow-Origin', origin);
  headers.set('Vary', 'Origin');
  headers.set('Access-Control-Allow-Headers', 'Authorization, Content-Type, X-SyncNow-Ticket, Range');
  headers.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    if (request.method === 'OPTIONS') {
      return withCORS(request, new Response(null, { status: 204 }));
    }
    const res = await handleRequest(request, env);
    return withCORS(request, res);
  },
};

function compareRelaySemVer(a: string, b: string): number {
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

function acceptsHTML(request: Request): boolean {
  return (request.headers.get('Accept') || '').toLowerCase().includes('text/html');
}

function withQuotaHeaders(request: Request, cfg: DynamicRelayConfig, bodyText?: string): Request {
  const headers = new Headers(request.headers);
  headers.set('X-SyncNow-Max-Envelopes', String(cfg.maxEnvelopes || 500));
  headers.set('X-SyncNow-Max-Blob-MB', String(cfg.maxBlobMB || 25));
  headers.set('X-SyncNow-Blob-TTL-Days', String(cfg.blobTTLDays || 7));
  if (bodyText !== undefined) {
    headers.set('Content-Type', 'application/json');
    return new Request(request.url, {
      method: request.method,
      headers,
      body: bodyText,
    });
  }
  return new Request(request, { headers });
}

function expectedPartCipherLen(claims: TmpTicketClaims, partIdx: number): number {
  if (partIdx < 0 || partIdx >= claims.totalChunks) return -1;
  if (partIdx < claims.totalChunks - 1) return claims.chunkCipher;
  return claims.totalCipher - (claims.totalChunks - 1) * claims.chunkCipher;
}

async function resolveTmpClaimsForRead(
  request: Request,
  env: Env,
  transferID: string,
  groupHash: string,
): Promise<{ claims?: TmpTicketClaims; errorResponse?: Response }> {
  const url = new URL(request.url);
  const rawTicket =
    (request.headers.get('X-SyncNow-Ticket') || url.searchParams.get('ticket') || '').trim();
  if (rawTicket) {
    const verified = await verifyTmpTicket(env, rawTicket, transferID, groupHash || undefined);
    if (verified) return { claims: verified };
  }
  const authRes = await authenticateRequest(request, env);
  if (!authRes.principal) {
    return { errorResponse: authRes.errorResponse || apiError(401, 'unauthorized', 'unauthorized') };
  }
  const metaStub = env.META_STORE.get(env.META_STORE.idFromName('global'));
  const lookupRes = await metaStub.fetch(
    `https://internal/internal/tmp/lookup/${transferID}?group=${encodeURIComponent(groupHash)}`,
  );
  if (!lookupRes.ok) {
    return { errorResponse: lookupRes };
  }
  const claims = (await lookupRes.json()) as TmpTicketClaims;
  return { claims };
}

async function handleEdgeTmpRoutes(request: Request, env: Env, url: URL): Promise<Response> {
  const path = url.pathname;
  const metaStub = env.META_STORE.get(env.META_STORE.idFromName('global'));

  if (path === '/v1/tmp/init' && request.method === 'POST') {
    const authRes = await authenticateRequest(request, env);
    if (!authRes.principal) {
      return authRes.errorResponse || apiError(401, 'unauthorized', 'unauthorized');
    }
    const body = (await request.json().catch(() => null)) as Record<string, unknown> | null;
    if (!body) return apiError(400, 'invalid_json', 'invalid json payload');
    if (
      !SAFE_ID_REGEX.test(String(body.transferID || '')) ||
      !SAFE_ID_REGEX.test(String(body.groupHash || ''))
    ) {
      return apiError(400, 'invalid_params', 'valid transferID and groupHash are required');
    }
    return metaStub.fetch('https://internal/internal/tmp/init', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...body, cfg: authRes.cfg }),
    });
  }

  const rest = path.slice('/v1/tmp/'.length);
  const segs = rest.split('/');
  const transferID = segs[0] || '';
  if (!SAFE_ID_REGEX.test(transferID)) {
    return apiError(400, 'invalid_transfer_id', 'valid transferID is required');
  }
  const groupHash = (url.searchParams.get('group') || '').trim();

  // Single-segment GET (full stream / HTTP Range) or DELETE
  if (segs.length === 1) {
    if (request.method === 'DELETE') {
      const authRes = await authenticateRequest(request, env);
      if (!authRes.principal) {
        return authRes.errorResponse || apiError(401, 'unauthorized', 'unauthorized');
      }
      return metaStub.fetch(
        `https://internal/internal/tmp/${transferID}?group=${encodeURIComponent(groupHash)}`,
        { method: 'DELETE' },
      );
    }

    if (request.method === 'GET') {
      const { claims, errorResponse } = await resolveTmpClaimsForRead(
        request,
        env,
        transferID,
        groupHash,
      );
      if (!claims) return errorResponse!;

      // Fast Path: Stream directly from Cloudflare R2 at the Edge without touching any Durable Object!
      if (claims.backend === 'r2' && env.BLOBS) {
        const rangeHdr = request.headers.get('Range');
        if (rangeHdr && rangeHdr.startsWith('bytes=')) {
          const [startStr, endStr] = rangeHdr.slice(6).split('-');
          const start = Number(startStr || '0');
          const end = endStr ? Number(endStr) : claims.totalCipher - 1;
          if (Number.isFinite(start) && Number.isFinite(end) && start >= 0 && end >= start) {
            const length = Math.min(end, claims.totalCipher - 1) - start + 1;
            const obj = await env.BLOBS.get(claims.r2Key, { range: { offset: start, length } });
            if (!obj) return apiError(404, 'not_found', 'tmp blob not found');
            return new Response(obj.body, {
              status: 206,
              headers: {
                'Content-Type': 'application/octet-stream',
                'Content-Length': String(length),
                'Content-Range': `bytes ${start}-${start + length - 1}/${claims.totalCipher}`,
                'Accept-Ranges': 'bytes',
              },
            });
          }
        }
        const obj = await env.BLOBS.get(claims.r2Key);
        if (!obj) return apiError(404, 'not_found', 'tmp blob not found');
        return new Response(obj.body, {
          status: 200,
          headers: {
            'Content-Type': 'application/octet-stream',
            'Content-Length': String(obj.size),
            'Accept-Ranges': 'bytes',
          },
        });
      }

      const groupStub = env.RELAY_GROUP.get(env.RELAY_GROUP.idFromName(claims.grp));
      return groupStub.fetch(
        `https://internal/internal/do-tmp/${transferID}?totalChunks=${claims.totalChunks}&totalCipher=${claims.totalCipher}`,
      );
    }
    return apiError(405, 'method_not_allowed', 'method not allowed');
  }

  // POST /v1/tmp/:id/complete
  if (segs.length === 2 && segs[1] === 'complete' && request.method === 'POST') {
    const authRes = await authenticateRequest(request, env);
    if (!authRes.principal) {
      return authRes.errorResponse || apiError(401, 'unauthorized', 'unauthorized');
    }
    const body = (await request.json().catch(() => ({}))) as Record<string, unknown>;
    return metaStub.fetch('https://internal/internal/tmp/complete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...body, transferID }),
    });
  }

  // POST /v1/tmp/:id/ack
  if (segs.length === 2 && segs[1] === 'ack' && request.method === 'POST') {
    const authRes = await authenticateRequest(request, env);
    if (!authRes.principal) {
      return authRes.errorResponse || apiError(401, 'unauthorized', 'unauthorized');
    }
    const body = (await request.json().catch(() => ({}))) as Record<string, unknown>;
    return metaStub.fetch('https://internal/internal/tmp/ack', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        ...body,
        transferID,
        ackGraceMinutes: authRes.cfg.tmpAckGraceMinutes,
      }),
    });
  }

  // PUT/GET /v1/tmp/:id/parts/:idx
  if (segs.length === 3 && segs[1] === 'parts') {
    const partIdx = Number(segs[2]);
    if (!Number.isInteger(partIdx) || partIdx < 0 || partIdx >= MAX_TMP_CHUNKS_PER_TRANSFER) {
      return apiError(400, 'invalid_part', 'invalid part index');
    }

    if (request.method === 'PUT' || request.method === 'POST') {
      const rawTicket =
        (request.headers.get('X-SyncNow-Ticket') || url.searchParams.get('ticket') || '').trim();
      let claims = rawTicket
        ? await verifyTmpTicket(env, rawTicket, transferID, groupHash || undefined)
        : null;
      if (!claims) {
        return apiError(401, 'invalid_ticket', 'valid X-SyncNow-Ticket is required for part upload');
      }
      const wantLen = expectedPartCipherLen(claims, partIdx);
      if (wantLen <= 0) {
        return apiError(400, 'invalid_part', 'part index out of range');
      }
      const clHeader = request.headers.get('Content-Length');
      if (clHeader && Number(clHeader) !== wantLen) {
        return apiError(
          400,
          'part_size_mismatch',
          `expected ${wantLen} bytes, got ${clHeader}`,
        );
      }

      // Edge-Direct R2 upload (zero bytes pass through Durable Objects!)
      if (claims.backend === 'r2' && env.BLOBS) {
        if (!request.body) return apiError(400, 'empty_body', 'empty upload body');
        let etag = '';
        if (claims.totalChunks === 1) {
          const data = new Uint8Array(await request.arrayBuffer());
          if (data.byteLength !== wantLen) {
            return apiError(
              400,
              'part_size_mismatch',
              `expected ${wantLen} bytes, got ${data.byteLength}`,
            );
          }
          const obj = await env.BLOBS.put(claims.r2Key, data, {
            httpMetadata: { contentType: 'application/octet-stream' },
          });
          etag = obj.etag;
        } else {
          if (!claims.uploadId) {
            return apiError(400, 'missing_upload_id', 'missing R2 multipart uploadId');
          }
          const mpu = env.BLOBS.resumeMultipartUpload(claims.r2Key, claims.uploadId);
          const uploaded = await mpu.uploadPart(partIdx + 1, request.body);
          etag = uploaded.etag;
        }
        // Record lightweight part etag in MetaStoreDO for resumable `init` / `complete`
        await metaStub.fetch('https://internal/internal/tmp/record-part', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ transferID, partIndex: partIdx, etag }),
        });
        return jsonResponse({ partIndex: partIdx, partNumber: partIdx + 1, etag });
      }

      // DO SQLite fallback when R2 is not bound
      const groupStub = env.RELAY_GROUP.get(env.RELAY_GROUP.idFromName(claims.grp));
      const doRes = await groupStub.fetch(
        `https://internal/internal/do-tmp/${transferID}/parts/${partIdx}?expectedLen=${wantLen}`,
        { method: 'PUT', body: request.body },
      );
      if (!doRes.ok) return doRes;
      const partData = (await doRes.json()) as { partIndex: number; partNumber: number; etag: string };
      await metaStub.fetch('https://internal/internal/tmp/record-part', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ transferID, partIndex: partIdx, etag: partData.etag }),
      });
      return jsonResponse(partData);
    }

    if (request.method === 'GET') {
      const { claims, errorResponse } = await resolveTmpClaimsForRead(
        request,
        env,
        transferID,
        groupHash,
      );
      if (!claims) return errorResponse!;
      const partLen = expectedPartCipherLen(claims, partIdx);
      if (partLen <= 0) return apiError(400, 'invalid_part', 'part index out of range');

      if (claims.backend === 'r2' && env.BLOBS) {
        const offset = partIdx * claims.chunkCipher;
        const obj = await env.BLOBS.get(claims.r2Key, { range: { offset, length: partLen } });
        if (!obj) return apiError(404, 'not_found', 'tmp part not found');
        return new Response(obj.body, {
          status: 200,
          headers: {
            'Content-Type': 'application/octet-stream',
            'Content-Length': String(partLen),
          },
        });
      }

      const groupStub = env.RELAY_GROUP.get(env.RELAY_GROUP.idFromName(claims.grp));
      return groupStub.fetch(`https://internal/internal/do-tmp/${transferID}/parts/${partIdx}`);
    }
  }

  return apiError(404, 'not_found', 'Not found');
}

async function handleRequest(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname;

  if (path === '/ping' && request.method === 'GET') {
    return jsonResponse({ ok: true });
  }

  if (path === '/favicon.ico' && request.method === 'GET') {
    return new Response(null, {
      status: 204,
      headers: { 'Cache-Control': 'public, max-age=86400' },
    });
  }

  if (path === '/setup/' && request.method === 'GET') {
    return new Response(null, {
      status: 302,
      headers: {
        Location: '/setup',
        'Cache-Control': 'no-store',
        'X-Robots-Tag': 'noindex, nofollow',
      },
    });
  }

  if (path === '/' && request.method === 'GET') {
    const cfg = await loadRuntimeConfig(env);
    if (!cfg.initialized) {
      return new Response(null, {
        status: 302,
        headers: {
          Location: '/setup',
          'Cache-Control': 'no-store',
          'X-Robots-Tag': 'noindex, nofollow',
        },
      });
    }
    const admin = await isSetupAdmin(request, cfg);
    if (!admin) {
      if (acceptsHTML(request)) {
        return new Response(SETUP_UI_HTML, {
          status: 401,
          headers: {
            'Content-Type': 'text/html; charset=utf-8',
            'WWW-Authenticate': 'Bearer realm="syncnow-relay"',
            'Cache-Control': 'no-store',
            'X-Robots-Tag': 'noindex, nofollow',
          },
        });
      }
      return new Response(
        JSON.stringify({ error: 'unauthorized', message: 'authentication required' }),
        {
          status: 401,
          headers: {
            'Content-Type': 'application/json; charset=utf-8',
            'WWW-Authenticate': 'Bearer realm="syncnow-relay"',
            'Cache-Control': 'no-store',
            'X-Robots-Tag': 'noindex, nofollow',
          },
        },
      );
    }
    return new Response(SETUP_UI_HTML, {
      status: 200,
      headers: {
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'no-store',
        'X-Robots-Tag': 'noindex, nofollow',
      },
    });
  }

  if (path === '/setup' && request.method === 'GET') {
    return new Response(SETUP_UI_HTML, {
      status: 200,
      headers: {
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'no-store',
        'X-Robots-Tag': 'noindex, nofollow',
      },
    });
  }

  if (path === '/v1/setup/status' && request.method === 'GET') {
    const cfg = await loadRuntimeConfig(env, true);
    const storageBackend = env.BLOBS ? 'r2' : 'do_sqlite';
    if (!cfg.initialized) {
      return jsonResponse({
        initialized: false,
        runtime: 'cloudflare-workers',
        storageBackend,
        version: RELAY_VERSION,
        siteName: cfg.siteName,
        authMode: cfg.authMode,
        authAPI: cfg.authAPI,
        maxEnvelopes: cfg.maxEnvelopes,
        maxBlobMB: cfg.maxBlobMB,
        blobTTLDays: cfg.blobTTLDays,
        maxTmpFileMB: cfg.maxTmpFileMB,
        maxTmpTotalMB: cfg.maxTmpTotalMB,
        tmpTTLHours: cfg.tmpTTLHours,
        tmpAckGraceMinutes: cfg.tmpAckGraceMinutes,
        r2Enabled: Boolean(env.BLOBS),
        isAdmin: false,
      });
    }
    const admin = await isSetupAdmin(request, cfg);
    if (!admin) {
      return new Response(
        JSON.stringify({
          error: 'unauthorized',
          message: 'admin authentication required',
          initialized: true,
        }),
        {
          status: 401,
          headers: {
            'Content-Type': 'application/json; charset=utf-8',
            'WWW-Authenticate': 'Bearer realm="syncnow-relay"',
            'Cache-Control': 'no-store',
          },
        },
      );
    }
    const metaStub = env.META_STORE.get(env.META_STORE.idFromName('global'));
    const summaryRes = await metaStub.fetch('https://internal/internal/admin-summary', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(cfg),
    });
    const summary = (await summaryRes.json()) as {
      tmpStats: TmpStatsSummary;
      deviceTokens: DeviceTokenRecord[];
    };

    return jsonResponse({
      initialized: true,
      runtime: 'cloudflare-workers',
      storageBackend,
      version: RELAY_VERSION,
      siteName: cfg.siteName,
      authMode: cfg.authMode,
      authAPI: cfg.authAPI,
      ownerDisplayName: cfg.ownerDisplayName || '',
      ownerUserID: cfg.ownerUserID || '',
      ownerLocked: cfg.authMode === 'xtags_owner' && cfg.allowUsers.length > 0,
      allowUsersCount: cfg.allowUsers.length,
      allowUsers: cfg.allowUsers,
      maxEnvelopes: cfg.maxEnvelopes,
      maxBlobMB: cfg.maxBlobMB,
      blobTTLDays: cfg.blobTTLDays,
      maxTmpFileMB: cfg.maxTmpFileMB,
      maxTmpTotalMB: cfg.maxTmpTotalMB,
      tmpTTLHours: cfg.tmpTTLHours,
      tmpAckGraceMinutes: cfg.tmpAckGraceMinutes,
      tmpStats: summary.tmpStats,
      deviceTokens: summary.deviceTokens,
      r2Enabled: Boolean(env.BLOBS),
      isAdmin: true,
    });
  }

  if (path === '/v1/setup/relay-update' && request.method === 'GET') {
    const cfg = await loadRuntimeConfig(env, true);
    if (cfg.initialized && !(await isSetupAdmin(request, cfg))) {
      return new Response(
        JSON.stringify({ error: 'unauthorized', message: 'admin authentication required' }),
        {
          status: 401,
          headers: {
            'Content-Type': 'application/json; charset=utf-8',
            'WWW-Authenticate': 'Bearer realm="syncnow-relay"',
            'Cache-Control': 'no-store',
          },
        },
      );
    }

    let latestVersion = RELAY_VERSION;
    let hasUpdate = false;
    let checkError: string | undefined;
    try {
      const up = await fetch(
        'https://raw.githubusercontent.com/zsai001/syncnow/main/package.json',
        {
          headers: {
            Accept: 'application/json',
            'Cache-Control': 'no-cache',
            'User-Agent': `syncnow-relay/${RELAY_VERSION}`,
          },
        },
      );
      if (up.ok) {
        const parsed = (await up.json().catch(() => null)) as { version?: string } | null;
        const v = (parsed?.version || '').trim();
        if (v) {
          latestVersion = v;
          hasUpdate = compareRelaySemVer(RELAY_VERSION, v) < 0;
        } else {
          checkError = 'invalid version metadata';
        }
      } else {
        checkError = `upstream returned HTTP ${up.status}`;
      }
    } catch {
      checkError = 'unable to reach GitHub release metadata';
    }

    return jsonResponse(
      {
        currentVersion: RELAY_VERSION,
        latestVersion,
        hasUpdate,
        runtime: 'cloudflare-workers',
        repoUrl: 'https://github.com/zsai001/syncnow',
        deployUrl: 'https://xtags.top/deploy/syncnow',
        ...(checkError ? { checkError } : {}),
      },
      200,
      { 'Cache-Control': 'no-store' },
    );
  }

  if (path === '/v1/setup/verify-xtags' && request.method === 'POST') {
    const cfg = await loadRuntimeConfig(env, true);
    const body = (await request.json().catch(() => null)) as {
      authCode?: string;
      token?: string;
      authAPI?: string;
    } | null;
    if (!body) return apiError(400, 'invalid_json', 'invalid request body');
    if (cfg.initialized && cfg.authMode === 'static_token') {
      return apiError(401, 'unauthorized', 'xtags admin login is disabled in static token mode');
    }
    const targetAuthAPI = cfg.initialized
      ? cfg.authAPI || 'https://api.xtags.top'
      : body.authAPI || 'https://api.xtags.top';
    const res = await verifyOrExchangeXTags(targetAuthAPI, body.authCode || '', body.token || '');
    if (res.errorResponse || !res.user || !res.token) {
      return res.errorResponse || apiError(400, 'xtags_verify_failed', 'verification failed');
    }
    if (cfg.initialized && (!cfg.ownerUserID || res.user.id !== cfg.ownerUserID)) {
      return apiError(401, 'unauthorized', 'not authorized as relay administrator');
    }
    return jsonResponse({ token: res.token, user: res.user });
  }

  if (path === '/v1/setup/complete' && request.method === 'POST') {
    const cfg = await loadRuntimeConfig(env, true);
    if (cfg.initialized && !(await isSetupAdmin(request, cfg))) {
      return apiError(401, 'unauthorized', 'admin authentication required to modify existing setup');
    }

    const req = (await request.json().catch(() => null)) as {
      siteName?: string;
      authMode?: 'xtags_owner' | 'xtags_multi' | 'static_token';
      authAPI?: string;
      xtagsToken?: string;
      allowUsers?: string[];
      staticToken?: string;
      adminToken?: string;
      maxEnvelopes?: number;
      maxBlobMB?: number;
      blobTTLDays?: number;
      maxTmpFileMB?: number;
      maxTmpTotalMB?: number;
      tmpTTLHours?: number;
      tmpAckGraceMinutes?: number;
    } | null;
    if (!req) return apiError(400, 'invalid_json', 'invalid json payload');

    const mode = req.authMode;
    if (mode !== 'xtags_owner' && mode !== 'xtags_multi' && mode !== 'static_token') {
      return apiError(400, 'invalid_mode', 'authMode must be xtags_owner, xtags_multi, or static_token');
    }

    const maxTmpFileCup = env.BLOBS ? 102400 : 512;
    const maxTmpFileMB =
      req.maxTmpFileMB && req.maxTmpFileMB >= 1 && req.maxTmpFileMB <= maxTmpFileCup
        ? req.maxTmpFileMB
        : cfg.maxTmpFileMB;
    const rawTmpTotalMB =
      req.maxTmpTotalMB && req.maxTmpTotalMB >= 1 && req.maxTmpTotalMB <= 1024000
        ? req.maxTmpTotalMB
        : cfg.maxTmpTotalMB;

    const next: DynamicRelayConfig = {
      ...cfg,
      initialized: true,
      siteName: (req.siteName || cfg.siteName || 'SyncNow Relay').trim(),
      authMode: mode,
      maxEnvelopes:
        req.maxEnvelopes && req.maxEnvelopes > 0 && req.maxEnvelopes <= 5000
          ? req.maxEnvelopes
          : cfg.maxEnvelopes,
      maxBlobMB:
        req.maxBlobMB && req.maxBlobMB > 0 && req.maxBlobMB <= 512
          ? req.maxBlobMB
          : cfg.maxBlobMB,
      blobTTLDays:
        req.blobTTLDays && req.blobTTLDays > 0 && req.blobTTLDays <= 365
          ? req.blobTTLDays
          : cfg.blobTTLDays,
      maxTmpFileMB,
      maxTmpTotalMB: Math.max(maxTmpFileMB, rawTmpTotalMB),
      tmpTTLHours:
        req.tmpTTLHours && req.tmpTTLHours >= 1 && req.tmpTTLHours <= 720
          ? req.tmpTTLHours
          : cfg.tmpTTLHours,
      tmpAckGraceMinutes:
        req.tmpAckGraceMinutes !== undefined &&
        Number.isFinite(req.tmpAckGraceMinutes) &&
        req.tmpAckGraceMinutes >= -1 &&
        req.tmpAckGraceMinutes <= 10080
          ? req.tmpAckGraceMinutes
          : cfg.tmpAckGraceMinutes,
      updatedAtMs: Date.now(),
    };
    if (req.adminToken && req.adminToken.trim()) {
      next.adminToken = req.adminToken.trim();
    }

    if (mode === 'static_token') {
      const tok = (req.staticToken || cfg.staticToken || '').trim();
      if (tok.length < 12) {
        return apiError(400, 'weak_token', 'staticToken must be at least 12 characters');
      }
      next.staticToken = tok;
      next.authAPI = '';
      next.allowUsers = [];
      next.ownerUserID = undefined;
      next.ownerDisplayName = undefined;
    } else {
      const apiBase = (req.authAPI || 'https://api.xtags.top').trim().replace(/\/+$/, '');
      next.authAPI = apiBase;
      next.staticToken = undefined;

      const tok = (req.xtagsToken || extractBearerToken(request) || '').trim();
      if (tok) {
        const verified = await verifyOrExchangeXTags(apiBase, '', tok);
        if (verified.errorResponse || !verified.user) {
          return verified.errorResponse || apiError(401, 'unauthorized', 'xtags verification failed');
        }
        next.ownerUserID = verified.user.id;
        next.ownerDisplayName = verified.user.displayName;
      } else if (!cfg.initialized || !next.ownerUserID) {
        return apiError(400, 'owner_required', 'valid xtags.top token is required to bind relay owner');
      }

      if (mode === 'xtags_owner') {
        const cleaned = Array.from(
          new Set((req.allowUsers || []).map((s) => s.trim()).filter(Boolean)),
        );
        next.allowUsers = cleaned.length > 0 ? cleaned : next.ownerUserID ? [next.ownerUserID] : [];
      } else {
        next.allowUsers = [];
      }
    }

    const metaStub = env.META_STORE.get(env.META_STORE.idFromName('global'));
    await metaStub.fetch('https://internal/internal/config', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(next),
    });
    invalidateConfigCache();
    return jsonResponse({ ok: true });
  }

  if (path === '/v1/setup/tmp-policy' && request.method === 'POST') {
    const cfg = await loadRuntimeConfig(env, true);
    if (!(await isSetupAdmin(request, cfg))) {
      return apiError(401, 'unauthorized', 'admin authentication required');
    }
    const req = (await request.json().catch(() => null)) as Partial<DynamicRelayConfig> | null;
    if (!req) return apiError(400, 'invalid_json', 'invalid json payload');

    const maxTmpFileCap = env.BLOBS ? 102400 : 512;
    const next: DynamicRelayConfig = { ...cfg, updatedAtMs: Date.now() };
    if (req.maxEnvelopes && req.maxEnvelopes >= 10 && req.maxEnvelopes <= 5000) {
      next.maxEnvelopes = req.maxEnvelopes;
    }
    if (req.maxBlobMB && req.maxBlobMB >= 1 && req.maxBlobMB <= 512) {
      next.maxBlobMB = req.maxBlobMB;
    }
    if (req.blobTTLDays && req.blobTTLDays >= 1 && req.blobTTLDays <= 365) {
      next.blobTTLDays = req.blobTTLDays;
    }
    if (req.maxTmpFileMB && req.maxTmpFileMB >= 1 && req.maxTmpFileMB <= maxTmpFileCap) {
      next.maxTmpFileMB = req.maxTmpFileMB;
    }
    if (req.maxTmpTotalMB && req.maxTmpTotalMB >= 1 && req.maxTmpTotalMB <= 1024000) {
      next.maxTmpTotalMB = req.maxTmpTotalMB;
    }
    if (req.tmpTTLHours && req.tmpTTLHours >= 1 && req.tmpTTLHours <= 720) {
      next.tmpTTLHours = req.tmpTTLHours;
    }
    if (
      req.tmpAckGraceMinutes !== undefined &&
      Number.isFinite(req.tmpAckGraceMinutes) &&
      req.tmpAckGraceMinutes >= -1 &&
      req.tmpAckGraceMinutes <= 10080
    ) {
      next.tmpAckGraceMinutes = req.tmpAckGraceMinutes;
    }
    next.maxTmpTotalMB = Math.max(next.maxTmpFileMB, next.maxTmpTotalMB);

    const metaStub = env.META_STORE.get(env.META_STORE.idFromName('global'));
    await metaStub.fetch('https://internal/internal/config', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(next),
    });
    invalidateConfigCache();

    const summaryRes = await metaStub.fetch('https://internal/internal/admin-summary', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(next),
    });
    const summary = (await summaryRes.json()) as { tmpStats: TmpStatsSummary };
    return jsonResponse({ ok: true, tmpStats: summary.tmpStats });
  }

  if (path === '/v1/setup/purge-tmp' && request.method === 'POST') {
    const cfg = await loadRuntimeConfig(env, true);
    if (!(await isSetupAdmin(request, cfg))) {
      return apiError(401, 'unauthorized', 'admin authentication required');
    }
    const metaStub = env.META_STORE.get(env.META_STORE.idFromName('global'));
    return metaStub.fetch('https://internal/internal/purge-tmp', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(cfg),
    });
  }

  if (path === '/v1/setup/reset' && request.method === 'POST') {
    const cfg = await loadRuntimeConfig(env, true);
    if (!(await isSetupAdmin(request, cfg))) {
      return apiError(401, 'unauthorized', 'admin authentication required');
    }
    const metaStub = env.META_STORE.get(env.META_STORE.idFromName('global'));
    await metaStub.fetch('https://internal/internal/config', { method: 'DELETE' });
    invalidateConfigCache();
    invalidateDeviceTokenCache();
    return jsonResponse({ ok: true });
  }

  // Scoped Device Tokens (`snr_dev_...`)
  if (path === '/v1/auth/device-tokens' || path.startsWith('/v1/auth/device-tokens/')) {
    const cfg = await loadRuntimeConfig(env);
    const metaStub = env.META_STORE.get(env.META_STORE.idFromName('global'));

    if (path.startsWith('/v1/auth/device-tokens/')) {
      if (request.method !== 'DELETE') return apiError(405, 'method_not_allowed', 'method not allowed');
      if (!(await isSetupAdmin(request, cfg))) {
        return apiError(401, 'unauthorized', 'admin authentication required');
      }
      const id = path.slice('/v1/auth/device-tokens/'.length);
      if (!SAFE_ID_REGEX.test(id)) return apiError(400, 'invalid_id', 'invalid token id');
      const res = await metaStub.fetch(`https://internal/internal/device-tokens/${id}`, {
        method: 'DELETE',
      });
      invalidateDeviceTokenCache();
      return res;
    }

    if (request.method === 'GET') {
      if (!(await isSetupAdmin(request, cfg))) {
        return apiError(401, 'unauthorized', 'admin authentication required');
      }
      return metaStub.fetch('https://internal/internal/device-tokens');
    }

    if (request.method === 'POST') {
      let roomID = '';
      if (await isSetupAdmin(request, cfg)) {
        roomID = cfg.ownerUserID || 'static-owner';
      } else {
        const authRes = await authenticateRequest(request, env);
        if (!authRes.principal) {
          return authRes.errorResponse || apiError(401, 'unauthorized', 'unauthorized');
        }
        if (authRes.principal.mode === 'device_token' || authRes.principal.mode === 'open') {
          return apiError(403, 'forbidden', 'scoped device tokens cannot mint new tokens');
        }
        roomID = authRes.principal.roomID;
      }
      const reqBody = (await request.json().catch(() => ({}))) as {
        label?: string;
        ttlDays?: number;
      };
      return metaStub.fetch('https://internal/internal/device-tokens/issue', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          label: reqBody.label,
          ttlDays: reqBody.ttlDays,
          roomID,
        }),
      });
    }
    return apiError(405, 'method_not_allowed', 'method not allowed');
  }

  // Health check
  if (path === '/health') {
    const authRes = await authenticateRequest(request, env);
    const { cfg } = authRes;
    let { principal } = authRes;
    if (!principal) {
      const token = extractBearerToken(request);
      if (token && cfg.adminToken && constantTimeEqual(token, cfg.adminToken)) {
        principal = {
          roomID: cfg.ownerUserID || (cfg.authMode === 'static_token' ? 'static-owner' : 'admin'),
          user: null,
          mode: 'static_token',
        };
      } else {
        return authRes.errorResponse || apiError(401, 'unauthorized', 'unauthorized');
      }
    }
    const authAPI = cfg.authMode === 'static_token' ? '' : (cfg.authAPI || '').trim();
    const userSummary = principal.user
      ? { id: principal.user.id, displayName: principal.user.displayName }
      : undefined;

    const capabilities = [
      'e2ee_relay',
      'e2ee_blobs',
      'tmp_chunked_blobs',
      'same_account_signaling',
      'group_key_vault',
      'ws_peer_tunnel',
      'device_tokens',
      'web_setup',
    ];
    if (authAPI) capabilities.push('xtags_auth');
    if (env.BLOBS) capabilities.push('r2_blobs');

    return jsonResponse({
      status: 'ok',
      service: 'syncnow-relay',
      runtime: 'cloudflare-workers',
      storageBackend: env.BLOBS ? 'r2' : 'do_sqlite',
      version: RELAY_VERSION,
      initialized: cfg.initialized,
      xtagsAuth: Boolean(authAPI),
      ownerLocked: cfg.authMode === 'xtags_owner' && cfg.allowUsers.length > 0,
      authenticated: principal.mode !== 'open',
      authMode: principal.mode,
      maxBlobMB: cfg.maxBlobMB,
      maxTmpFileMB: cfg.maxTmpFileMB,
      maxTmpTotalMB: cfg.maxTmpTotalMB,
      tmpTTLHours: cfg.tmpTTLHours,
      tmpAckGraceMinutes: cfg.tmpAckGraceMinutes,
      tmpChunkPlainBytes: DEFAULT_TMP_CHUNK_PLAIN_BYTES,
      user: userSummary,
      capabilities,
    });
  }

  // Chunked streaming Tmp Large File routes (`/v1/tmp/*`)
  if (path.startsWith('/v1/tmp/')) {
    return handleEdgeTmpRoutes(request, env, url);
  }

  // Legacy update routes
  if (path === '/v1/updates/check') {
    const metaStub = env.META_STORE.get(env.META_STORE.idFromName('global'));
    return metaStub.fetch(request);
  }

  if (path === '/v1/admin/updates') {
    const cfg = await loadRuntimeConfig(env);
    const expectedAdmin = (cfg.adminToken || cfg.staticToken || '').trim();
    const got = extractBearerToken(request);
    const okByToken = Boolean(expectedAdmin && got && constantTimeEqual(got, expectedAdmin));
    const okByOwner = !okByToken && (await isSetupAdmin(request, cfg));
    if (!okByToken && !okByOwner) {
      return apiError(401, 'unauthorized', 'invalid admin token');
    }
    const metaStub = env.META_STORE.get(env.META_STORE.idFromName('global'));
    return metaStub.fetch(request);
  }

  // Data, Signaling, Group Vault & Tunnel routes require valid auth
  const authRes = await authenticateRequest(request, env);
  const { cfg } = authRes;
  let { principal } = authRes;
  if (!principal && path === '/v1/signal/peers' && request.method === 'GET') {
    const token = extractBearerToken(request);
    if (token && cfg.adminToken && constantTimeEqual(token, cfg.adminToken)) {
      principal = {
        roomID: cfg.ownerUserID || (cfg.authMode === 'static_token' ? 'static-owner' : 'admin'),
        user: null,
        mode: 'static_token',
      };
    }
  }
  if (!principal) {
    return authRes.errorResponse || apiError(401, 'unauthorized', 'unauthorized');
  }

  if (
    path === '/v1/signal/ws' ||
    path === '/v1/signal/peers' ||
    path === '/v1/signal/group-vault' ||
    path === '/v1/tunnel/ws'
  ) {
    const roomStub = env.SIGNALING_ROOM.get(env.SIGNALING_ROOM.idFromName(principal.roomID));
    const fwdHeaders = new Headers(request.headers);
    fwdHeaders.set('X-SyncNow-Room-ID', principal.roomID);
    const fwdReq = new Request(request, { headers: fwdHeaders });
    return roomStub.fetch(fwdReq);
  }

  if (path === '/ws' || path === '/v1/sync' || path.startsWith('/v1/blobs/')) {
    const groupHash = (url.searchParams.get('group') || '').trim();
    if (!SAFE_ID_REGEX.test(groupHash)) {
      return apiError(400, 'invalid_group', 'valid group query parameter is required');
    }
    const groupStub = env.RELAY_GROUP.get(env.RELAY_GROUP.idFromName(groupHash));
    return groupStub.fetch(withQuotaHeaders(request, cfg));
  }

  if (path === '/v1/push' && request.method === 'POST') {
    const bodyText = await request.text();
    let parsed: { groupHash?: string };
    try {
      parsed = JSON.parse(bodyText) as { groupHash?: string };
    } catch {
      return apiError(400, 'invalid_json', 'invalid json');
    }
    const groupHash = (parsed.groupHash || '').trim();
    if (!SAFE_ID_REGEX.test(groupHash)) {
      return apiError(400, 'invalid_group', 'invalid groupHash');
    }
    const groupStub = env.RELAY_GROUP.get(env.RELAY_GROUP.idFromName(groupHash));
    return groupStub.fetch(withQuotaHeaders(request, cfg, bodyText));
  }

  return apiError(404, 'not_found', 'Not found');
}
