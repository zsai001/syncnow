import {
  apiError,
  DEVICE_TOKEN_PREFIX,
  type AuthPrincipal,
  type DeviceTokenRecord,
  type DynamicRelayConfig,
  type Env,
  type TmpTicketClaims,
  type XTagsUser,
} from './types.ts';

const CACHE_VALID_TTL_MS = 5 * 60 * 1000;
const CACHE_INVALID_TTL_MS = 15 * 1000;
const DEVICE_TOKEN_CACHE_TTL_MS = 30 * 1000;
const CONFIG_CACHE_TTL_MS = 5 * 1000;

interface CachedEntry {
  valid: boolean;
  user: XTagsUser | null;
  expiresAtMs: number;
}

interface CachedDeviceToken {
  valid: boolean;
  roomID: string;
  expiresAtMs: number;
}

const tokenCache = new Map<string, CachedEntry>();
const deviceTokenCache = new Map<string, CachedDeviceToken>();
let cachedRuntimeConfig: { cfg: DynamicRelayConfig; expiresAtMs: number } | null = null;
let cachedTicketSecretHex: string | null = null;
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

export function invalidateConfigCache(): void {
  cachedRuntimeConfig = null;
}

export function invalidateDeviceTokenCache(): void {
  deviceTokenCache.clear();
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

export async function sha256Hex(input: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', textEncoder.encode(input));
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function toBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i += 1) {
    binary += String.fromCharCode(bytes[i]!);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function fromBase64Url(str: string): Uint8Array | null {
  try {
    let b64 = str.replace(/-/g, '+').replace(/_/g, '/');
    while (b64.length % 4 !== 0) b64 += '=';
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

export async function getTicketSecretHex(env: Env): Promise<string> {
  if (cachedTicketSecretHex) return cachedTicketSecretHex;
  const metaStub = env.META_STORE.get(env.META_STORE.idFromName('global'));
  const res = await metaStub.fetch('https://internal/internal/ticket-secret');
  const data = (await res.json()) as { secretHex: string };
  cachedTicketSecretHex = data.secretHex;
  return data.secretHex;
}

export async function signTmpTicket(secretHex: string, claims: TmpTicketClaims): Promise<string> {
  const payload = toBase64Url(textEncoder.encode(JSON.stringify(claims)));
  const key = await crypto.subtle.importKey(
    'raw',
    textEncoder.encode(secretHex),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', key, textEncoder.encode(payload)));
  return `v1.${payload}.${toBase64Url(sig)}`;
}

export async function verifyTmpTicket(
  env: Env,
  rawTicket: string,
  expectedTransferID: string,
  expectedGroupHash?: string,
): Promise<TmpTicketClaims | null> {
  const parts = (rawTicket || '').trim().split('.');
  if (parts.length !== 3 || parts[0] !== 'v1') return null;
  const sigBytes = fromBase64Url(parts[2]!);
  const payloadBytes = fromBase64Url(parts[1]!);
  if (!sigBytes || !payloadBytes) return null;

  const secretHex = await getTicketSecretHex(env);
  const key = await crypto.subtle.importKey(
    'raw',
    textEncoder.encode(secretHex),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['verify'],
  );
  const ok = await crypto.subtle.verify('HMAC', key, sigBytes, textEncoder.encode(parts[1]!));
  if (!ok) return null;

  try {
    const claims = JSON.parse(textDecoder.decode(payloadBytes)) as TmpTicketClaims;
    if (claims.tid !== expectedTransferID) return null;
    if (expectedGroupHash && claims.grp !== expectedGroupHash) return null;
    if (Date.now() >= claims.exp) return null;
    return claims;
  } catch {
    return null;
  }
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

  const hasR2 = Boolean(env.BLOBS);
  const defaultTmpFileMB = hasR2 ? 1024 : 128;
  const defaultTmpTotalMB = hasR2 ? 8192 : 1024;
  const defaultTmpTTLHours = hasR2 ? 12 : 4;
  const parsedGrace = Number(env.SYNCNOW_TMP_ACK_GRACE_MINUTES ?? '30');

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
    maxTmpFileMB: Number(env.SYNCNOW_MAX_TMP_FILE_MB || String(defaultTmpFileMB)) || defaultTmpFileMB,
    maxTmpTotalMB: Number(env.SYNCNOW_MAX_TMP_TOTAL_MB || String(defaultTmpTotalMB)) || defaultTmpTotalMB,
    tmpTTLHours: Number(env.SYNCNOW_TMP_TTL_HOURS || String(defaultTmpTTLHours)) || defaultTmpTTLHours,
    tmpAckGraceMinutes: Number.isFinite(parsedGrace) && parsedGrace >= -1 ? parsedGrace : 30,
    updatedAtMs: 0,
  };
}

export function normalizeRuntimeConfig(raw: Partial<DynamicRelayConfig>, env: Env): DynamicRelayConfig {
  const base = defaultConfigFromEnv(env);
  const maxTmpFileMB = raw.maxTmpFileMB && raw.maxTmpFileMB > 0 ? raw.maxTmpFileMB : base.maxTmpFileMB;
  const rawTotal = raw.maxTmpTotalMB && raw.maxTmpTotalMB > 0 ? raw.maxTmpTotalMB : base.maxTmpTotalMB;
  const maxTmpTotalMB = Math.max(maxTmpFileMB, rawTotal);
  const tmpTTLHours = raw.tmpTTLHours && raw.tmpTTLHours > 0 ? raw.tmpTTLHours : base.tmpTTLHours;
  const tmpAckGraceMinutes =
    raw.tmpAckGraceMinutes !== undefined && Number.isFinite(raw.tmpAckGraceMinutes) && raw.tmpAckGraceMinutes >= -1
      ? raw.tmpAckGraceMinutes
      : base.tmpAckGraceMinutes;

  return {
    ...base,
    ...raw,
    allowUsers: Array.isArray(raw.allowUsers) ? raw.allowUsers : base.allowUsers,
    maxEnvelopes: raw.maxEnvelopes && raw.maxEnvelopes > 0 ? raw.maxEnvelopes : base.maxEnvelopes,
    maxBlobMB: raw.maxBlobMB && raw.maxBlobMB > 0 ? raw.maxBlobMB : base.maxBlobMB,
    blobTTLDays: raw.blobTTLDays && raw.blobTTLDays > 0 ? raw.blobTTLDays : base.blobTTLDays,
    maxTmpFileMB,
    maxTmpTotalMB,
    tmpTTLHours,
    tmpAckGraceMinutes,
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
    const stored = (await res.json().catch(() => null)) as Partial<DynamicRelayConfig> | null;
    cfg = stored ? normalizeRuntimeConfig(stored, env) : defaultConfigFromEnv(env);
  } else {
    cfg = defaultConfigFromEnv(env);
  }
  cachedRuntimeConfig = { cfg, expiresAtMs: now + CONFIG_CACHE_TTL_MS };
  return cfg;
}

async function verifyDeviceToken(env: Env, rawToken: string): Promise<string | null> {
  const tokenHash = await sha256Hex(rawToken);
  const now = Date.now();
  const cached = deviceTokenCache.get(tokenHash);
  if (cached && now < cached.expiresAtMs) {
    return cached.valid ? cached.roomID : null;
  }

  const metaStub = env.META_STORE.get(env.META_STORE.idFromName('global'));
  const res = await metaStub.fetch('https://internal/internal/device-tokens/verify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ tokenHash }),
  });
  if (!res.ok) {
    deviceTokenCache.set(tokenHash, { valid: false, roomID: '', expiresAtMs: now + 10_000 });
    return null;
  }
  const data = (await res.json()) as { valid: boolean; record?: DeviceTokenRecord };
  if (!data.valid || !data.record?.roomID) {
    deviceTokenCache.set(tokenHash, { valid: false, roomID: '', expiresAtMs: now + 10_000 });
    return null;
  }
  deviceTokenCache.set(tokenHash, {
    valid: true,
    roomID: data.record.roomID,
    expiresAtMs: now + DEVICE_TOKEN_CACHE_TTL_MS,
  });
  return data.record.roomID;
}

export async function verifyXTagsTokenDirect(
  apiBase: string,
  rawToken: string,
  allowedUsers?: Set<string>,
): Promise<{ user?: XTagsUser; errorResponse?: Response }> {
  const cacheKey = `${apiBase}:${await sha256Hex(rawToken)}`;
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
  if (!token || token.startsWith(DEVICE_TOKEN_PREFIX)) return false;
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

  // 2. Scoped revocable device token (`snr_dev_...`)
  if (token.startsWith(DEVICE_TOKEN_PREFIX)) {
    const roomID = await verifyDeviceToken(env, token);
    if (roomID) {
      return { principal: { roomID, user: null, mode: 'device_token' }, cfg };
    }
    return { cfg, errorResponse: apiError(401, 'unauthorized', 'invalid or revoked device token') };
  }

  // 3. Unified xtags.top Bearer token authentication
  if (authAPI && token) {
    const { user, errorResponse } = await verifyXTagsTokenDirect(authAPI, token, allowedUsers);
    if (errorResponse || !user) {
      return { cfg, errorResponse: errorResponse || apiError(401, 'unauthorized', 'unauthorized') };
    }
    return { principal: { roomID: user.id, user, mode: 'xtags' }, cfg };
  }

  // 4. Explicit open mode (neither static token nor xtags API configured)
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
