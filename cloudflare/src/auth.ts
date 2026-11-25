import {
  apiError,
  type AuthPrincipal,
  type DynamicRelayConfig,
  type Env,
  type XTagsUser,
} from './types.ts';

const CACHE_VALID_TTL_MS = 5 * 60 * 1000;
const CACHE_INVALID_TTL_MS = 15 * 1000;
const CONFIG_CACHE_TTL_MS = 5 * 1000;

interface CachedEntry {
  valid: boolean;
  user: XTagsUser | null;
  expiresAtMs: number;
}

const tokenCache = new Map<string, CachedEntry>();
let cachedRuntimeConfig: { cfg: DynamicRelayConfig; expiresAtMs: number } | null = null;
const textEncoder = new TextEncoder();

export function invalidateConfigCache(): void {
  cachedRuntimeConfig = null;
}

export function extractBearerToken(request: Request): string {
  const auth = (request.headers.get('Authorization') || '').trim();
  if (auth.startsWith('Bearer ')) {
    return auth.slice(7).trim();
  }
  const url = new URL(request.url);
  return (url.searchParams.get('token') || '').trim();
}

export function constantTimeEqual(a: string, b: string): boolean {
  const ba = textEncoder.encode(a);
  const bb = textEncoder.encode(b);
  if (ba.length !== bb.length) return false;
  let diff = 0;
  for (let i = 0; i < ba.length; i += 1) {
    diff |= ba[i]! ^ bb[i]!;
  }
  return diff === 0;
}

async function hashTokenKey(token: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', textEncoder.encode(token));
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export function defaultConfigFromEnv(env: Env): DynamicRelayConfig {
  const allowUsers = (env.SYNCNOW_ALLOW_USERS || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  const staticToken = (env.SYNCNOW_RELAY_TOKEN || '').trim();
  const authAPI =
    env.SYNCNOW_AUTH_API === undefined
      ? 'https://api.xtags.top'
      : env.SYNCNOW_AUTH_API.trim().replace(/\/+$/, '');
  const envConfigured = Boolean(staticToken || allowUsers.length > 0);
  const authMode: DynamicRelayConfig['authMode'] =
    staticToken && !authAPI ? 'static_token' : 'xtags_owner';

  return {
    initialized: envConfigured,
    siteName: 'SyncNow Relay',
    authMode,
    authAPI,
    ownerUserID: allowUsers[0] || undefined,
    allowUsers,
    staticToken: staticToken || undefined,
    adminToken: (env.SYNCNOW_ADMIN_TOKEN || staticToken || '').trim() || undefined,
    maxEnvelopes: Number(env.SYNCNOW_MAX_ENVELOPES || '500') || 500,
    maxBlobMB: Number(env.SYNCNOW_MAX_BLOB_MB || '25') || 25,
    blobTTLDays: Number(env.SYNCNOW_BLOB_TTL_DAYS || '7') || 7,
    updatedAtMs: 0,
  };
}

export async function loadRuntimeConfig(env: Env, bypassCache = false): Promise<DynamicRelayConfig> {
  const now = Date.now();
  if (!bypassCache && cachedRuntimeConfig && now < cachedRuntimeConfig.expiresAtMs) {
    return cachedRuntimeConfig.cfg;
  }
  const metaStub = env.META_STORE.get(env.META_STORE.idFromName('global'));
  const res = await metaStub.fetch('https://internal/internal/config');
  let cfg: DynamicRelayConfig;
  if (res.ok) {
    const stored = (await res.json().catch(() => null)) as DynamicRelayConfig | null;
    cfg = stored ?? defaultConfigFromEnv(env);
  } else {
    cfg = defaultConfigFromEnv(env);
  }
  cachedRuntimeConfig = { cfg, expiresAtMs: now + CONFIG_CACHE_TTL_MS };
  return cfg;
}

export async function verifyXTagsTokenDirect(
  apiBase: string,
  rawToken: string,
  allowedUsers?: Set<string>,
): Promise<{ user?: XTagsUser; errorResponse?: Response }> {
  const cacheKey = `${apiBase}:${await hashTokenKey(rawToken)}`;
  const now = Date.now();
  const cached = tokenCache.get(cacheKey);
  if (cached && now < cached.expiresAtMs) {
    if (!cached.valid || !cached.user) {
      return { errorResponse: apiError(401, 'unauthorized', 'invalid or expired xtags token') };
    }
    if (allowedUsers && allowedUsers.size > 0 && !allowedUsers.has(cached.user.id)) {
      return {
        errorResponse: apiError(
          403,
          'forbidden_account',
          'xtags account is not allowed on this self-hosted relay',
        ),
      };
    }
    return { user: cached.user };
  }

  let res: Response;
  try {
    res = await fetch(`${apiBase}/v1/auth/me`, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${rawToken}`,
        Accept: 'application/json',
      },
    });
  } catch {
    return { errorResponse: apiError(502, 'upstream_error', 'failed to reach xtags auth api') };
  }

  if (res.status === 401 || res.status === 403) {
    putCache(cacheKey, { valid: false, user: null, expiresAtMs: now + CACHE_INVALID_TTL_MS });
    return { errorResponse: apiError(401, 'unauthorized', 'xtags token rejected') };
  }
  if (!res.ok) {
    return { errorResponse: apiError(502, 'upstream_error', 'xtags auth api returned error') };
  }

  const body = (await res.json().catch(() => null)) as {
    authenticated?: boolean;
    user?: XTagsUser | null;
  } | null;

  if (!body?.authenticated || !body.user?.id) {
    putCache(cacheKey, { valid: false, user: null, expiresAtMs: now + CACHE_INVALID_TTL_MS });
    return { errorResponse: apiError(401, 'unauthorized', 'xtags token not authenticated') };
  }

  putCache(cacheKey, { valid: true, user: body.user, expiresAtMs: now + CACHE_VALID_TTL_MS });

  if (allowedUsers && allowedUsers.size > 0 && !allowedUsers.has(body.user.id)) {
    return {
      errorResponse: apiError(
        403,
        'forbidden_account',
        'xtags account is not allowed on this self-hosted relay',
      ),
    };
  }
  return { user: body.user };
}

export async function verifyOrExchangeXTags(
  apiBase: string,
  authCode: string,
  rawToken: string,
): Promise<{ user?: XTagsUser; token?: string; errorResponse?: Response }> {
  const cleanAPI = (apiBase || 'https://api.xtags.top').trim().replace(/\/+$/, '');
  const code = (authCode || '').replace(/[\s-]+/g, '').trim();
  if (code) {
    let res: Response;
    try {
      res = await fetch(`${cleanAPI}/v1/auth/syncnow-code/exchange`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({ code, label: 'SyncNow Relay Setup' }),
      });
    } catch {
      return { errorResponse: apiError(502, 'upstream_error', 'failed to reach xtags.top auth API') };
    }
    const parsed = (await res.json().catch(() => null)) as {
      token?: string;
      user?: XTagsUser;
      error?: string;
    } | null;
    if (!res.ok || !parsed?.token || !parsed.user?.id) {
      return {
        errorResponse: apiError(
          400,
          'xtags_verify_failed',
          parsed?.error || 'invalid or expired 6-digit code',
        ),
      };
    }
    return { user: parsed.user, token: parsed.token };
  }

  const tok = (rawToken || '').trim();
  if (!tok) {
    return { errorResponse: apiError(400, 'missing_credential', 'authCode or token is required') };
  }
  const { user, errorResponse } = await verifyXTagsTokenDirect(cleanAPI, tok);
  if (errorResponse || !user) {
    return { errorResponse: errorResponse || apiError(401, 'unauthorized', 'invalid token') };
  }
  return { user, token: tok };
}

function putCache(key: string, entry: CachedEntry): void {
  if (tokenCache.size > 1024) {
    const now = Date.now();
    for (const [k, v] of tokenCache.entries()) {
      if (now >= v.expiresAtMs) tokenCache.delete(k);
    }
  }
  tokenCache.set(key, entry);
}

export async function isSetupAdmin(
  request: Request,
  cfg: DynamicRelayConfig,
): Promise<boolean> {
  const token = extractBearerToken(request);
  if (!token) return false;
  if (cfg.adminToken && constantTimeEqual(token, cfg.adminToken)) return true;
  if (cfg.staticToken && constantTimeEqual(token, cfg.staticToken)) return true;
  if (cfg.authAPI && cfg.ownerUserID) {
    const { user } = await verifyXTagsTokenDirect(cfg.authAPI, token);
    if (user && user.id === cfg.ownerUserID) return true;
  }
  return false;
}

export async function authenticateRequest(
  request: Request,
  env: Env,
): Promise<{ principal?: AuthPrincipal; cfg: DynamicRelayConfig; errorResponse?: Response }> {
  const cfg = await loadRuntimeConfig(env);
  const token = extractBearerToken(request);
  const staticToken = (cfg.staticToken || '').trim();
  const authAPI = cfg.authMode === 'static_token' ? '' : (cfg.authAPI || '').trim();
  const allowedUsers =
    cfg.authMode === 'xtags_owner' && cfg.allowUsers.length > 0
      ? new Set(cfg.allowUsers)
      : new Set<string>();

  // 1. Static token match
  if (staticToken && token && constantTimeEqual(token, staticToken)) {
    return { principal: { roomID: 'static-owner', user: null, mode: 'static_token' }, cfg };
  }

  // 2. Unified xtags.top Bearer token authentication
  if (authAPI && token) {
    const { user, errorResponse } = await verifyXTagsTokenDirect(authAPI, token, allowedUsers);
    if (errorResponse || !user) {
      return { cfg, errorResponse: errorResponse || apiError(401, 'unauthorized', 'unauthorized') };
    }
    return { principal: { roomID: user.id, user, mode: 'xtags' }, cfg };
  }

  // 3. Explicit open mode (neither static token nor xtags API configured)
  if (!staticToken && !authAPI) {
    return { principal: { roomID: 'open', user: null, mode: 'open' }, cfg };
  }

  return {
    cfg,
    errorResponse: apiError(
      401,
      'unauthorized',
      'valid xtags.top Bearer token or relay token is required',
    ),
  };
}
