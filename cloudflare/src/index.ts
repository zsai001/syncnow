import {
  authenticateRequest,
  constantTimeEqual,
  extractBearerToken,
  invalidateConfigCache,
  isSetupAdmin,
  loadRuntimeConfig,
  verifyOrExchangeXTags,
} from './auth.ts';
import { SETUP_UI_HTML } from './setup_ui.ts';
import {
  apiError,
  jsonResponse,
  RELAY_VERSION,
  SAFE_ID_REGEX,
  type DynamicRelayConfig,
  type Env,
} from './types.ts';

export { MetaStoreDO, RelayGroupDO, SignalingRoomDO } from './objects.ts';

function withCORS(request: Request, response: Response): Response {
  const origin = request.headers.get('Origin');
  if (!origin || response.status === 101) return response;
  const headers = new Headers(response.headers);
  headers.set('Access-Control-Allow-Origin', origin);
  headers.set('Vary', 'Origin');
  headers.set('Access-Control-Allow-Headers', 'Authorization, Content-Type');
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

async function handleRequest(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname;

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

  // 0. Default-deny root `/` once initialized; browsers with Accept: text/html receive the
  // zero-leak static Web Console shell on HTTP 401 so unlocked sessions and unlock UI work smoothly.
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
    if (!cfg.initialized) {
      return jsonResponse({
        initialized: false,
        runtime: 'cloudflare-workers',
        version: RELAY_VERSION,
        siteName: cfg.siteName,
        authMode: cfg.authMode,
        authAPI: cfg.authAPI,
        maxEnvelopes: cfg.maxEnvelopes,
        maxBlobMB: cfg.maxBlobMB,
        blobTTLDays: cfg.blobTTLDays,
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
    return jsonResponse({
      initialized: true,
      runtime: 'cloudflare-workers',
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
    } | null;
    if (!req) return apiError(400, 'invalid_json', 'invalid json payload');

    const mode = req.authMode;
    if (mode !== 'xtags_owner' && mode !== 'xtags_multi' && mode !== 'static_token') {
      return apiError(400, 'invalid_mode', 'authMode must be xtags_owner, xtags_multi, or static_token');
    }

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

  if (path === '/v1/setup/reset' && request.method === 'POST') {
    const cfg = await loadRuntimeConfig(env, true);
    if (!(await isSetupAdmin(request, cfg))) {
      return apiError(401, 'unauthorized', 'admin authentication required');
    }
    const metaStub = env.META_STORE.get(env.META_STORE.idFromName('global'));
    await metaStub.fetch('https://internal/internal/config', { method: 'DELETE' });
    invalidateConfigCache();
    return jsonResponse({ ok: true });
  }

  // 1. Health check (requires valid client auth or admin token; compatible with SyncNow "Test Connection")
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

    const capabilities = ['e2ee_relay', 'e2ee_blobs', 'same_account_signaling', 'updates', 'web_setup'];
    if (authAPI) capabilities.push('xtags_auth');
    if (env.BLOBS) capabilities.push('r2_blobs');

    return jsonResponse({
      status: 'ok',
      service: 'syncnow-relay',
      runtime: 'cloudflare-workers',
      version: RELAY_VERSION,
      initialized: cfg.initialized,
      xtagsAuth: Boolean(authAPI),
      ownerLocked: cfg.authMode === 'xtags_owner' && cfg.allowUsers.length > 0,
      authenticated: principal.mode !== 'open',
      user: userSummary,
      capabilities,
    });
  }

  // 2. Auto-Update / Force-Update public check (no auth required)
  if (path === '/v1/updates/check') {
    const metaStub = env.META_STORE.get(env.META_STORE.idFromName('global'));
    return metaStub.fetch(request);
  }

  // 3. Admin release manifest publish
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

  // 4. All data & signaling routes require valid xtags.top Bearer token (or static token)
  //    Admin token is also accepted on read-only `/v1/signal/peers` for the Web Console.
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

  // 5. Same-Account Signaling & Peer Matching (isolated strictly by verified xtags userID!)
  if (path === '/v1/signal/ws' || path === '/v1/signal/peers') {
    const roomStub = env.SIGNALING_ROOM.get(env.SIGNALING_ROOM.idFromName(principal.roomID));
    const fwdHeaders = new Headers(request.headers);
    fwdHeaders.set('X-SyncNow-Room-ID', principal.roomID);
    const fwdReq = new Request(request, { headers: fwdHeaders });
    return roomStub.fetch(fwdReq);
  }

  // 6. E2EE Clipboard Relay & Encrypted File Blobs (isolated by groupHash)
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
