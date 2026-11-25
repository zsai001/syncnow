var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// cloudflare/src/types.ts
var SAFE_ID_REGEX = /^[a-zA-Z0-9._-]{1,128}$/;
var RELAY_VERSION = "0.3.2";
function jsonResponse(payload, status = 200, extraHeaders) {
  const headers = new Headers(extraHeaders);
  headers.set("Content-Type", "application/json");
  return new Response(JSON.stringify(payload), { status, headers });
}
__name(jsonResponse, "jsonResponse");
function apiError(status, code, message) {
  return jsonResponse({ error: code, message }, status);
}
__name(apiError, "apiError");

// cloudflare/src/auth.ts
var CACHE_VALID_TTL_MS = 5 * 60 * 1e3;
var CACHE_INVALID_TTL_MS = 15 * 1e3;
var CONFIG_CACHE_TTL_MS = 5 * 1e3;
var tokenCache = /* @__PURE__ */ new Map();
var cachedRuntimeConfig = null;
var textEncoder = new TextEncoder();
function invalidateConfigCache() {
  cachedRuntimeConfig = null;
}
__name(invalidateConfigCache, "invalidateConfigCache");
function extractBearerToken(request) {
  const auth = (request.headers.get("Authorization") || "").trim();
  if (auth.startsWith("Bearer ")) {
    return auth.slice(7).trim();
  }
  const url = new URL(request.url);
  return (url.searchParams.get("token") || "").trim();
}
__name(extractBearerToken, "extractBearerToken");
function constantTimeEqual(a, b) {
  const ba = textEncoder.encode(a);
  const bb = textEncoder.encode(b);
  if (ba.length !== bb.length) return false;
  let diff = 0;
  for (let i = 0; i < ba.length; i += 1) {
    diff |= ba[i] ^ bb[i];
  }
  return diff === 0;
}
__name(constantTimeEqual, "constantTimeEqual");
async function hashTokenKey(token) {
  const digest = await crypto.subtle.digest("SHA-256", textEncoder.encode(token));
  return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, "0")).join("");
}
__name(hashTokenKey, "hashTokenKey");
function defaultConfigFromEnv(env) {
  const allowUsers = (env.SYNCNOW_ALLOW_USERS || "").split(",").map((s) => s.trim()).filter(Boolean);
  const staticToken = (env.SYNCNOW_RELAY_TOKEN || "").trim();
  const authAPI = env.SYNCNOW_AUTH_API === void 0 ? "https://api.xtags.top" : env.SYNCNOW_AUTH_API.trim().replace(/\/+$/, "");
  const envConfigured = Boolean(staticToken || allowUsers.length > 0);
  const authMode = staticToken && !authAPI ? "static_token" : "xtags_owner";
  return {
    initialized: envConfigured,
    siteName: "SyncNow Relay",
    authMode,
    authAPI,
    ownerUserID: allowUsers[0] || void 0,
    allowUsers,
    staticToken: staticToken || void 0,
    adminToken: (env.SYNCNOW_ADMIN_TOKEN || staticToken || "").trim() || void 0,
    maxEnvelopes: Number(env.SYNCNOW_MAX_ENVELOPES || "500") || 500,
    maxBlobMB: Number(env.SYNCNOW_MAX_BLOB_MB || "25") || 25,
    blobTTLDays: Number(env.SYNCNOW_BLOB_TTL_DAYS || "7") || 7,
    updatedAtMs: 0
  };
}
__name(defaultConfigFromEnv, "defaultConfigFromEnv");
async function loadRuntimeConfig(env, bypassCache = false) {
  const now = Date.now();
  if (!bypassCache && cachedRuntimeConfig && now < cachedRuntimeConfig.expiresAtMs) {
    return cachedRuntimeConfig.cfg;
  }
  const metaStub = env.META_STORE.get(env.META_STORE.idFromName("global"));
  const res = await metaStub.fetch("https://internal/internal/config");
  let cfg;
  if (res.ok) {
    const stored = await res.json().catch(() => null);
    cfg = stored ?? defaultConfigFromEnv(env);
  } else {
    cfg = defaultConfigFromEnv(env);
  }
  cachedRuntimeConfig = { cfg, expiresAtMs: now + CONFIG_CACHE_TTL_MS };
  return cfg;
}
__name(loadRuntimeConfig, "loadRuntimeConfig");
async function verifyXTagsTokenDirect(apiBase, rawToken, allowedUsers) {
  const cacheKey = `${apiBase}:${await hashTokenKey(rawToken)}`;
  const now = Date.now();
  const cached = tokenCache.get(cacheKey);
  if (cached && now < cached.expiresAtMs) {
    if (!cached.valid || !cached.user) {
      return { errorResponse: apiError(401, "unauthorized", "invalid or expired xtags token") };
    }
    if (allowedUsers && allowedUsers.size > 0 && !allowedUsers.has(cached.user.id)) {
      return {
        errorResponse: apiError(
          403,
          "forbidden_account",
          "xtags account is not allowed on this self-hosted relay"
        )
      };
    }
    return { user: cached.user };
  }
  let res;
  try {
    res = await fetch(`${apiBase}/v1/auth/me`, {
      method: "GET",
      headers: {
        Authorization: `Bearer ${rawToken}`,
        Accept: "application/json"
      }
    });
  } catch {
    return { errorResponse: apiError(502, "upstream_error", "failed to reach xtags auth api") };
  }
  if (res.status === 401 || res.status === 403) {
    putCache(cacheKey, { valid: false, user: null, expiresAtMs: now + CACHE_INVALID_TTL_MS });
    return { errorResponse: apiError(401, "unauthorized", "xtags token rejected") };
  }
  if (!res.ok) {
    return { errorResponse: apiError(502, "upstream_error", "xtags auth api returned error") };
  }
  const body = await res.json().catch(() => null);
  if (!body?.authenticated || !body.user?.id) {
    putCache(cacheKey, { valid: false, user: null, expiresAtMs: now + CACHE_INVALID_TTL_MS });
    return { errorResponse: apiError(401, "unauthorized", "xtags token not authenticated") };
  }
  putCache(cacheKey, { valid: true, user: body.user, expiresAtMs: now + CACHE_VALID_TTL_MS });
  if (allowedUsers && allowedUsers.size > 0 && !allowedUsers.has(body.user.id)) {
    return {
      errorResponse: apiError(
        403,
        "forbidden_account",
        "xtags account is not allowed on this self-hosted relay"
      )
    };
  }
  return { user: body.user };
}
__name(verifyXTagsTokenDirect, "verifyXTagsTokenDirect");
async function verifyOrExchangeXTags(apiBase, authCode, rawToken) {
  const cleanAPI = (apiBase || "https://api.xtags.top").trim().replace(/\/+$/, "");
  const code = (authCode || "").replace(/[\s-]+/g, "").trim();
  if (code) {
    let res;
    try {
      res = await fetch(`${cleanAPI}/v1/auth/syncnow-code/exchange`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        body: JSON.stringify({ code, label: "SyncNow Relay Setup" })
      });
    } catch {
      return { errorResponse: apiError(502, "upstream_error", "failed to reach xtags.top auth API") };
    }
    const parsed = await res.json().catch(() => null);
    if (!res.ok || !parsed?.token || !parsed.user?.id) {
      return {
        errorResponse: apiError(
          400,
          "xtags_verify_failed",
          parsed?.error || "invalid or expired 6-digit code"
        )
      };
    }
    return { user: parsed.user, token: parsed.token };
  }
  const tok = (rawToken || "").trim();
  if (!tok) {
    return { errorResponse: apiError(400, "missing_credential", "authCode or token is required") };
  }
  const { user, errorResponse } = await verifyXTagsTokenDirect(cleanAPI, tok);
  if (errorResponse || !user) {
    return { errorResponse: errorResponse || apiError(401, "unauthorized", "invalid token") };
  }
  return { user, token: tok };
}
__name(verifyOrExchangeXTags, "verifyOrExchangeXTags");
function putCache(key, entry) {
  if (tokenCache.size > 1024) {
    const now = Date.now();
    for (const [k, v] of tokenCache.entries()) {
      if (now >= v.expiresAtMs) tokenCache.delete(k);
    }
  }
  tokenCache.set(key, entry);
}
__name(putCache, "putCache");
async function isSetupAdmin(request, cfg) {
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
__name(isSetupAdmin, "isSetupAdmin");
async function authenticateRequest(request, env) {
  const cfg = await loadRuntimeConfig(env);
  const token = extractBearerToken(request);
  const staticToken = (cfg.staticToken || "").trim();
  const authAPI = cfg.authMode === "static_token" ? "" : (cfg.authAPI || "").trim();
  const allowedUsers = cfg.authMode === "xtags_owner" && cfg.allowUsers.length > 0 ? new Set(cfg.allowUsers) : /* @__PURE__ */ new Set();
  if (staticToken && token && constantTimeEqual(token, staticToken)) {
    return { principal: { roomID: "static-owner", user: null, mode: "static_token" }, cfg };
  }
  if (authAPI && token) {
    const { user, errorResponse } = await verifyXTagsTokenDirect(authAPI, token, allowedUsers);
    if (errorResponse || !user) {
      return { cfg, errorResponse: errorResponse || apiError(401, "unauthorized", "unauthorized") };
    }
    return { principal: { roomID: user.id, user, mode: "xtags" }, cfg };
  }
  if (!staticToken && !authAPI) {
    return { principal: { roomID: "open", user: null, mode: "open" }, cfg };
  }
  return {
    cfg,
    errorResponse: apiError(
      401,
      "unauthorized",
      "valid xtags.top Bearer token or relay token is required"
    )
  };
}
__name(authenticateRequest, "authenticateRequest");

// cloudflare/src/setup_ui.ts
var SETUP_UI_HTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>SyncNow Relay \xB7 Setup</title>
  <link id="appFavicon" rel="icon" type="image/png" href="data:image/png;base64,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" />
  <style>
    :root {
      color-scheme: light dark;
      --bg: #0b0d14;
      --card: #121622;
      --card-2: #171c2b;
      --border: rgba(255, 255, 255, 0.10);
      --text: #eef2ff;
      --muted: #94a3b8;
      --accent: #38bdf8;
      --accent-2: #6366f1;
      --ok: #22c55e;
      --warn: #f59e0b;
      --err: #ef4444;
    }
    @media (prefers-color-scheme: light) {
      :root {
        --bg: #f4f6fb;
        --card: #ffffff;
        --card-2: #f8fafc;
        --border: rgba(15, 23, 42, 0.10);
        --text: #0f172a;
        --muted: #64748b;
        --accent: #0284c7;
        --accent-2: #4f46e5;
      }
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: -apple-system, BlinkMacSystemFont, "SF Pro Text", "Segoe UI", Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.5;
      min-height: 100vh;
      padding: 28px 16px 60px;
    }
    .wrap { max-width: 740px; margin: 0 auto; }
    .topbar {
      display: flex; align-items: center; justify-content: space-between;
      gap: 12px; margin-bottom: 20px; flex-wrap: wrap;
    }
    .brand { display: flex; align-items: center; gap: 12px; }
    .logo {
      width: 42px; height: 42px; border-radius: 10px;
      display: block; flex-shrink: 0; object-fit: cover;
      box-shadow: 0 8px 22px rgba(37, 99, 235, 0.28);
    }
    .brand h1 { margin: 0; font-size: 19px; font-weight: 700; }
    .brand p { margin: 2px 0 0; font-size: 12.5px; color: var(--muted); }
    .pills { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
    .pill {
      display: inline-flex; align-items: center; gap: 6px;
      padding: 5px 11px; border-radius: 999px; font-size: 12px; font-weight: 600;
      border: 1px solid var(--border); background: var(--card);
    }
    .pill.ok { color: var(--ok); border-color: rgba(34, 197, 94, 0.35); background: rgba(34, 197, 94, 0.10); }
    .pill.warn { color: var(--warn); border-color: rgba(245, 158, 11, 0.35); background: rgba(245, 158, 11, 0.10); }
    .pill.accent { color: var(--accent); border-color: rgba(56, 189, 248, 0.35); background: rgba(56, 189, 248, 0.10); }
    .dot { width: 7px; height: 7px; border-radius: 50%; background: currentColor; }
    .card {
      background: var(--card); border: 1px solid var(--border);
      border-radius: 18px; padding: 22px; margin-bottom: 16px;
      box-shadow: 0 10px 30px rgba(0, 0, 0, 0.12);
    }
    .card h2 { margin: 0 0 6px; font-size: 16px; font-weight: 700; }
    .sub { margin: 0 0 16px; font-size: 13px; color: var(--muted); }
    .grid-3 { display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; margin-bottom: 16px; }
    .grid-2 { display: grid; grid-template-columns: repeat(2, 1fr); gap: 12px; }
    @media (max-width: 640px) {
      .grid-3, .grid-2 { grid-template-columns: 1fr; }
    }
    .mode-card {
      border: 1.5px solid var(--border); border-radius: 13px; padding: 13px;
      background: var(--card-2); cursor: pointer; text-align: left;
      color: var(--text); transition: border-color 0.15s, background 0.15s;
    }
    .mode-card.active {
      border-color: var(--accent);
      background: rgba(56, 189, 248, 0.09);
    }
    .mode-card .title { font-size: 13.5px; font-weight: 700; margin-bottom: 4px; }
    .mode-card .desc { font-size: 11.5px; color: var(--muted); line-height: 1.4; }
    label { display: block; font-size: 12px; font-weight: 600; color: var(--muted); margin: 12px 0 6px; }
    input[type="text"], input[type="password"], input[type="number"], textarea {
      width: 100%; padding: 10px 12px; border-radius: 10px;
      border: 1px solid var(--border); background: var(--card-2); color: var(--text);
      font-size: 13.5px; outline: none; font-family: inherit;
    }
    input.mono, textarea.mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
    input:focus, textarea:focus { border-color: var(--accent); }
    .row { display: flex; gap: 8px; align-items: center; }
    .row > input { flex: 1; }
    .btn {
      display: inline-flex; align-items: center; justify-content: center; gap: 7px;
      padding: 10px 16px; border-radius: 10px; font-size: 13px; font-weight: 600;
      border: 1px solid var(--border); background: var(--card-2); color: var(--text);
      cursor: pointer; text-decoration: none; white-space: nowrap;
      transition: opacity 0.15s, transform 0.08s;
    }
    .btn:hover { opacity: 0.92; }
    .btn:active { transform: scale(0.985); }
    .btn:disabled { opacity: 0.5; cursor: not-allowed; }
    .btn.primary {
      background: linear-gradient(135deg, var(--accent), var(--accent-2));
      color: #fff; border: none;
    }
    .btn.danger { color: var(--err); border-color: rgba(239, 68, 68, 0.35); background: rgba(239, 68, 68, 0.08); }
    .btn.sm { padding: 7px 12px; font-size: 12px; border-radius: 8px; }
    .notice {
      padding: 11px 13px; border-radius: 11px; font-size: 12.5px; margin-top: 12px;
      border: 1px solid var(--border); background: var(--card-2);
    }
    .notice.ok { border-color: rgba(34, 197, 94, 0.35); background: rgba(34, 197, 94, 0.10); color: var(--ok); }
    .notice.err { border-color: rgba(239, 68, 68, 0.35); background: rgba(239, 68, 68, 0.10); color: var(--err); }
    .notice.info { border-color: rgba(56, 189, 248, 0.35); background: rgba(56, 189, 248, 0.10); color: var(--accent); }
    .kv-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 10px; margin: 14px 0; }
    @media (max-width: 560px) { .kv-grid { grid-template-columns: 1fr; } }
    .kv {
      padding: 11px 13px; border-radius: 12px;
      border: 1px solid var(--border); background: var(--card-2);
    }
    .kv .k { font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.04em; }
    .kv .v { font-size: 13.5px; font-weight: 600; margin-top: 3px; word-break: break-all; }
    .hidden { display: none !important; }
    .footer { text-align: center; font-size: 12px; color: var(--muted); margin-top: 22px; }
    .footer a { color: var(--accent); text-decoration: none; }
    .code-box {
      padding: 11px 13px; border-radius: 11px; background: var(--card-2);
      border: 1px solid var(--border); font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      font-size: 12.5px; word-break: break-all;
    }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="topbar">
      <div class="brand">
        <img class="logo" id="brandLogo" alt="SyncNow" width="42" height="42" />
        <div>
          <h1 id="siteTitle">SyncNow Relay</h1>
          <p id="siteSubtitle">E2EE \u526A\u8D34\u677F \xB7 \u52A0\u5BC6\u6587\u4EF6 \xB7 \u540C\u8D26\u53F7\u4FE1\u4EE4\u81EA\u5EFA\u4E2D\u7EE7</p>
        </div>
      </div>
      <div class="pills">
        <span class="pill ok" id="statusPill"><span class="dot"></span><span id="statusText">Loading\u2026</span></span>
        <span class="pill accent" id="runtimePill">v0.3.2</span>
        <button class="btn sm" type="button" id="langBtn">EN</button>
      </div>
    </div>

    <!-- FIRST-RUN SETUP WIZARD -->
    <div id="setupWizardCard" class="card hidden">
      <h2 data-i18n="setupTitle">\u521D\u59CB\u5316\u4F60\u7684\u81EA\u5EFA\u4E2D\u7EE7</h2>
      <p class="sub" data-i18n="setupDesc">\u5B89\u88C5\u5DF2\u6210\u529F\uFF01\u65E0\u9700\u624B\u6539\u73AF\u5883\u53D8\u91CF\uFF0C\u5728\u5F53\u524D\u9875\u9762 30 \u79D2\u5B8C\u6210\u673A\u4E3B\u7ED1\u5B9A\u4E0E\u5B89\u5168\u7B56\u7565\u914D\u7F6E\u3002</p>

      <label data-i18n="chooseMode">1. \u9009\u62E9\u9274\u6743\u4E0E\u8BBF\u95EE\u6A21\u5F0F</label>
      <div class="grid-3" id="modeSelector">
        <button type="button" class="mode-card active" data-mode="xtags_owner">
          <div class="title" data-i18n="modeOwnerTitle">xtags \u673A\u4E3B\u72EC\u5360\uFF08\u63A8\u8350\uFF09</div>
          <div class="desc" data-i18n="modeOwnerDesc">\u7ED1\u5B9A\u4F60\u7684 xtags.top \u8D26\u53F7\uFF0C\u4EC5\u5141\u8BB8\u4F60\u81EA\u5DF1\uFF08\u6216\u6307\u5B9A\u767D\u540D\u5355\uFF09\u4F7F\u7528\uFF0C\u540C\u8D26\u53F7\u514D\u914D\u5BF9\u76F4\u8FDE\u3002</div>
        </button>
        <button type="button" class="mode-card" data-mode="xtags_multi">
          <div class="title" data-i18n="modeMultiTitle">xtags \u591A\u8D26\u53F7\u9694\u79BB</div>
          <div class="desc" data-i18n="modeMultiDesc">\u5141\u8BB8\u4EFB\u610F\u6709\u6548 xtags.top \u8D26\u53F7\u4F7F\u7528\uFF0C\u6309 userId \u4E25\u683C\u9694\u79BB\u623F\u95F4\uFF1B\u4ECD\u7ED1\u5B9A\u4F60\u4F5C\u4E3A\u7BA1\u7406\u5458\u3002</div>
        </button>
        <button type="button" class="mode-card" data-mode="static_token">
          <div class="title" data-i18n="modeStaticTitle">\u79BB\u7EBF\u9759\u6001\u4EE4\u724C</div>
          <div class="desc" data-i18n="modeStaticDesc">\u4E0D\u8FDE\u63A5 xtags.top \u5916\u7F51\uFF0C\u6240\u6709\u8BBE\u5907\u4F7F\u7528\u540C\u4E00\u4E2A\u9759\u6001 Bearer Token\uFF08\u9002\u5408\u7EAF\u5185\u7F51\uFF09\u3002</div>
        </button>
      </div>

      <!-- xtags auth section -->
      <div id="xtagsAuthPanel">
        <label data-i18n="xtagsVerifyLabel">2. \u901A\u8FC7 xtags.top \u9A8C\u8BC1\u673A\u4E3B\u8EAB\u4EFD\uFF08\u4F7F\u7528 6 \u4F4D\u6388\u6743\u7801\u6216\u4EE4\u724C\uFF09</label>
        <div class="row" style="margin-bottom:10px; flex-wrap:wrap;">
          <a class="btn primary" id="openXTagsCodeBtn" href="https://xtags.top/auth/extension?client=syncnow&mode=code" rel="noreferrer" data-i18n="getSixDigitCode">
            \u524D\u5F80 xtags.top \u6388\u6743\u5E76\u83B7\u53D6 6 \u4F4D\u7801 \u2197
          </a>
          <span style="font-size:12px; color:var(--muted);" data-i18n="xtagsCodeHint">\u5728 xtags.top \u786E\u8BA4\u540E\u53EF\u4E00\u952E\u8FD4\u56DE\u81EA\u52A8\u9A8C\u8BC1\uFF0C\u6216\u590D\u5236 6 \u4F4D\u6570\u5B57\u7801\u586B\u5230\u4E0B\u65B9</span>
        </div>

        <div class="row">
          <input type="text" id="setupXTagsInput" class="mono" placeholder="\u8F93\u5165 6 \u4F4D\u6388\u6743\u7801\uFF08\u5982 482917\uFF09\u6216\u7C98\u8D34 xtags_ext_... \u4EE4\u724C" />
          <button type="button" class="btn" id="verifyXTagsBtn" data-i18n="verifyBtn">\u9A8C\u8BC1\u8EAB\u4EFD</button>
        </div>

        <div id="verifiedUserBox" class="notice ok hidden"></div>

        <div id="allowUsersWrap" class="hidden">
          <label data-i18n="allowUsersLabel">\u5141\u8BB8\u4F7F\u7528\u7684 xtags \u7528\u6237 ID \u767D\u540D\u5355\uFF08\u9017\u53F7\u5206\u9694\uFF0C\u9ED8\u8BA4\u4EC5\u4F60\u672C\u4EBA\uFF09</label>
          <input type="text" id="setupAllowUsers" class="mono" placeholder="usr_..." />
        </div>
      </div>

      <!-- static token section -->
      <div id="staticAuthPanel" class="hidden">
        <label data-i18n="staticTokenLabel">2. \u8BBE\u7F6E\u9759\u6001\u8BBF\u95EE\u4EE4\u724C\uFF08\u540C\u65F6\u7528\u4E8E\u7BA1\u7406\u5458\u767B\u5F55\uFF09</label>
        <div class="row">
          <input type="text" id="setupStaticToken" class="mono" placeholder="\u81F3\u5C11 12 \u4F4D\u968F\u673A\u5BC6\u94A5" />
          <button type="button" class="btn" id="genStaticTokenBtn" data-i18n="genRandomBtn">\u968F\u673A\u751F\u6210</button>
        </div>
      </div>

      <details style="margin-top:14px;">
        <summary style="cursor:pointer; font-size:12.5px; color:var(--muted); font-weight:600;" data-i18n="advancedOptions">\u9AD8\u7EA7\u53C2\u6570\uFF08\u4E2D\u7EE7\u540D\u79F0 / \u914D\u989D / \u81EA\u5B9A\u4E49 Auth API\uFF09</summary>
        <div class="grid-2" style="margin-top:8px;">
          <div>
            <label data-i18n="siteNameLabel">\u4E2D\u7EE7\u540D\u79F0</label>
            <input type="text" id="setupSiteName" value="SyncNow Relay" />
          </div>
          <div>
            <label>xtags Auth API</label>
            <input type="text" id="setupAuthAPI" class="mono" value="https://api.xtags.top" />
          </div>
          <div>
            <label data-i18n="maxEnvLabel">\u6BCF\u7EC4\u4FDD\u7559\u526A\u8D34\u677F\u6761\u6570</label>
            <input type="number" id="setupMaxEnvelopes" value="500" min="50" max="5000" />
          </div>
          <div>
            <label data-i18n="maxBlobLabel">\u5355\u6587\u4EF6\u6700\u5927\u4F53\u79EF (MB)</label>
            <input type="number" id="setupMaxBlobMB" value="25" min="1" max="512" />
          </div>
          <div>
            <label data-i18n="blobTTLLabel">\u52A0\u5BC6\u6587\u4EF6\u4FDD\u7559\u5929\u6570</label>
            <input type="number" id="setupBlobTTLDays" value="7" min="1" max="365" />
          </div>
          <div>
            <label data-i18n="adminTokenOptLabel">\u66F4\u65B0\u53D1\u5E03 Admin Token\uFF08\u53EF\u9009\uFF09</label>
            <input type="password" id="setupAdminToken" class="mono" placeholder="\u7559\u7A7A\u5219\u6CBF\u7528\u673A\u4E3B\u8EAB\u4EFD\u6216\u9759\u6001\u4EE4\u724C" />
          </div>
        </div>
      </details>

      <div style="margin-top:18px; display:flex; gap:10px; flex-wrap:wrap;">
        <button type="button" class="btn primary" id="completeSetupBtn" data-i18n="completeSetupBtn">\u5B8C\u6210\u521D\u59CB\u5316\u5E76\u4FDD\u5B58\u914D\u7F6E</button>
        <button type="button" class="btn hidden" id="cancelEditBtn" data-i18n="cancelBtn">\u8FD4\u56DE\u6982\u89C8</button>
      </div>
      <div id="setupMsg" class="notice hidden"></div>
    </div>

    <!-- INITIALIZED OVERVIEW & CLIENT QUICK CONNECT -->
    <div id="overviewCard" class="card hidden">
      <div style="display:flex; justify-content:space-between; align-items:center; gap:10px; flex-wrap:wrap;">
        <div>
          <h2 data-i18n="readyTitle">\u4E2D\u7EE7\u5DF2\u5C31\u7EEA\uFF0C\u53EF\u7ACB\u5373\u5728 SyncNow \u4E2D\u63A5\u5165</h2>
          <p class="sub" style="margin-bottom:0;" data-i18n="readyDesc">\u6240\u6709\u526A\u8D34\u677F\u4E0E\u6587\u4EF6\u5747\u7531\u5BA2\u6237\u7AEF ChaCha20-Poly1305 \u7AEF\u5230\u7AEF\u52A0\u5BC6\uFF0C\u670D\u52A1\u7AEF\u5168\u7A0B\u96F6\u660E\u6587\u3002</p>
        </div>
        <div class="row">
          <button type="button" class="btn sm" id="checkRelayUpdateBtn" data-i18n="checkUpdateBtn">\u68C0\u67E5\u5347\u7EA7</button>
          <button type="button" class="btn sm" id="openAdminLoginBtn" data-i18n="manageConfigBtn">\u7BA1\u7406\u914D\u7F6E</button>
          <button type="button" class="btn sm" id="adminLogoutBtn" data-i18n="lockSessionBtn">\u9501\u5B9A\u9000\u51FA</button>
        </div>
      </div>

      <div class="kv-grid">
        <div class="kv">
          <div class="k" data-i18n="kvRelayURL">\u81EA\u5EFA\u4E2D\u7EE7\u5730\u5740</div>
          <div class="v mono" id="relayUrlDisplay">-</div>
        </div>
        <div class="kv">
          <div class="k" data-i18n="kvAuthMode">\u9274\u6743\u6A21\u5F0F</div>
          <div class="v" id="authModeDisplay">-</div>
        </div>
        <div class="kv">
          <div class="k" data-i18n="kvOwner">\u7ED1\u5B9A\u673A\u4E3B</div>
          <div class="v" id="ownerDisplay">-</div>
        </div>
        <div class="kv">
          <div class="k" data-i18n="kvQuota">\u5B58\u50A8\u914D\u989D</div>
          <div class="v" id="quotaDisplay">-</div>
        </div>
      </div>

      <label data-i18n="clientConnectLabel">\u5728 SyncNow \u5BA2\u6237\u7AEF\u63A5\u5165\uFF08\u6253\u5F00\u300Cxtags.top \u7EDF\u4E00\u8D26\u53F7\u4E0E\u81EA\u5EFA\u4E2D\u7EE7\u300D\u7C98\u8D34\u4E0B\u65B9\u5730\u5740\uFF09</label>
      <div class="row" style="flex-wrap:wrap;">
        <div class="code-box" style="flex:1; min-width:220px;" id="relayUrlCode">-</div>
        <button type="button" class="btn" id="copyUrlBtn" data-i18n="copyUrlBtn">\u590D\u5236\u5730\u5740</button>
        <button type="button" class="btn" id="testHealthBtn" data-i18n="testHealthBtn">\u8FDE\u901A\u6D4B\u8BD5</button>
      </div>

      <div id="relayUpdateBox" class="hidden" style="margin-top:14px; padding:14px; border-radius:13px; border:1px solid var(--border); background:var(--card-2);">
        <div style="display:flex; justify-content:space-between; align-items:center; gap:10px; flex-wrap:wrap;">
          <div>
            <div style="font-size:13px; font-weight:700;" id="relayUpdateTitle">-</div>
            <div style="font-size:12px; color:var(--muted); margin-top:2px;" id="relayUpdateDesc">-</div>
          </div>
          <div class="row">
            <a class="btn sm primary hidden" id="relayUpgradeWebBtn" href="https://xtags.top/deploy/syncnow?mode=upgrade" target="_blank" rel="noreferrer">\u524D\u5F80\u4E00\u952E\u65E0\u635F\u5347\u7EA7 \u2197</a>
            <button type="button" class="btn sm" id="closeRelayUpdateBtn" data-i18n="closeBtn">\u6536\u8D77</button>
          </div>
        </div>
        <div id="relayUpgradeCmds" style="margin-top:10px; display:flex; flex-direction:column; gap:8px;"></div>
      </div>

      <div id="overviewNotice" class="notice hidden"></div>
    </div>

    <!-- ADMIN AUTH MODAL / CARD -->
    <div id="adminAuthCard" class="card hidden">
      <h2 data-i18n="adminLoginTitle">\u7BA1\u7406\u5458\u8EAB\u4EFD\u9A8C\u8BC1</h2>
      <p class="sub" id="adminLoginDesc">\u8BF7\u8F93\u5165\u673A\u4E3B xtags.top 6 \u4F4D\u6388\u6743\u7801\uFF08\u6216\u4EE4\u724C / \u9759\u6001\u7BA1\u7406\u4EE4\u724C\uFF09\u4EE5\u4FEE\u6539\u4E2D\u7EE7\u914D\u7F6E\u3002</p>
      <div class="row" style="margin-bottom:10px; flex-wrap:wrap;" id="adminXTagsShortcut">
        <a class="btn sm" id="adminXTagsCodeBtn" href="https://xtags.top/auth/extension?client=syncnow&mode=code" rel="noreferrer" data-i18n="getSixDigitCode">
          \u524D\u5F80 xtags.top \u6388\u6743\u5E76\u83B7\u53D6 6 \u4F4D\u7801 \u2197
        </a>
      </div>
      <div class="row">
        <input type="password" id="adminTokenInput" class="mono" placeholder="\u8F93\u5165 6 \u4F4D\u6388\u6743\u7801\u3001xtags_ext_... \u6216\u9759\u6001\u7BA1\u7406\u4EE4\u724C" />
        <button type="button" class="btn primary" id="adminUnlockBtn" data-i18n="unlockBtn">\u9A8C\u8BC1\u5E76\u8FDB\u5165\u8BBE\u7F6E</button>
        <button type="button" class="btn" id="adminCancelBtn" data-i18n="cancelBtn">\u53D6\u6D88</button>
      </div>
      <div id="adminAuthMsg" class="notice hidden"></div>
    </div>

    <!-- ADMIN ONLINE PEERS & DANGER ZONE -->
    <div id="adminPeersCard" class="card hidden">
      <div style="display:flex; justify-content:space-between; align-items:center; gap:10px; flex-wrap:wrap;">
        <div>
          <h2 data-i18n="onlinePeersTitle">\u5F53\u524D\u540C\u8D26\u53F7\u5728\u7EBF\u4FE1\u4EE4\u8BBE\u5907</h2>
          <p class="sub" style="margin-bottom:0;" data-i18n="onlinePeersDesc">\u901A\u8FC7 /v1/signal/ws \u5DF2\u8FDE\u63A5\u81F3\u6B64\u4E2D\u7EE7\u7684\u540C\u8D26\u53F7\u8BBE\u5907\u5217\u8868</p>
        </div>
        <div class="row">
          <button type="button" class="btn sm" id="refreshPeersBtn" data-i18n="refreshBtn">\u5237\u65B0</button>
          <button type="button" class="btn sm danger" id="resetSetupBtn" data-i18n="resetBtn">\u91CD\u7F6E\u521D\u59CB\u5316</button>
        </div>
      </div>
      <div id="peersListBox" style="margin-top:12px; font-size:13px; color:var(--muted);">-</div>
    </div>

    <div class="footer">
      <a href="https://xtags.top/syncnow" target="_blank" rel="noreferrer">SyncNow</a> \xB7 <a href="https://github.com/zsai001/syncnow" target="_blank" rel="noreferrer">Open-Source Relay</a> \xB7 Support <a href="https://x.com/zsai010" target="_blank" rel="noreferrer">@zsai010</a>
    </div>
  </div>

  <script>
    const I18N = {
      zh: {
        setupTitle: '\u521D\u59CB\u5316\u4F60\u7684\u81EA\u5EFA\u4E2D\u7EE7',
        setupDesc: '\u5B89\u88C5\u5DF2\u6210\u529F\uFF01\u65E0\u9700\u624B\u6539\u73AF\u5883\u53D8\u91CF\uFF0C\u5728\u5F53\u524D\u9875\u9762 30 \u79D2\u5B8C\u6210\u673A\u4E3B\u7ED1\u5B9A\u4E0E\u5B89\u5168\u7B56\u7565\u914D\u7F6E\u3002',
        chooseMode: '1. \u9009\u62E9\u9274\u6743\u4E0E\u8BBF\u95EE\u6A21\u5F0F',
        modeOwnerTitle: 'xtags \u673A\u4E3B\u72EC\u5360\uFF08\u63A8\u8350\uFF09',
        modeOwnerDesc: '\u7ED1\u5B9A\u4F60\u7684 xtags.top \u8D26\u53F7\uFF0C\u4EC5\u5141\u8BB8\u4F60\u81EA\u5DF1\uFF08\u6216\u6307\u5B9A\u767D\u540D\u5355\uFF09\u4F7F\u7528\uFF0C\u540C\u8D26\u53F7\u514D\u914D\u5BF9\u76F4\u8FDE\u3002',
        modeMultiTitle: 'xtags \u591A\u8D26\u53F7\u9694\u79BB',
        modeMultiDesc: '\u5141\u8BB8\u4EFB\u610F\u6709\u6548 xtags.top \u8D26\u53F7\u4F7F\u7528\uFF0C\u6309 userId \u4E25\u683C\u9694\u79BB\u623F\u95F4\uFF1B\u4ECD\u7ED1\u5B9A\u4F60\u4F5C\u4E3A\u7BA1\u7406\u5458\u3002',
        modeStaticTitle: '\u79BB\u7EBF\u9759\u6001\u4EE4\u724C',
        modeStaticDesc: '\u4E0D\u8FDE\u63A5 xtags.top \u5916\u7F51\uFF0C\u6240\u6709\u8BBE\u5907\u4F7F\u7528\u540C\u4E00\u4E2A\u9759\u6001 Bearer Token\uFF08\u9002\u5408\u7EAF\u5185\u7F51\uFF09\u3002',
        xtagsVerifyLabel: '2. \u901A\u8FC7 xtags.top \u9A8C\u8BC1\u673A\u4E3B\u8EAB\u4EFD\uFF08\u4E00\u952E\u6388\u6743\u6216 6 \u4F4D\u7801\uFF09',
        getSixDigitCode: '\u524D\u5F80 xtags.top \u6388\u6743\u5E76\u83B7\u53D6 6 \u4F4D\u7801 \u2197',
        xtagsCodeHint: '\u5728 xtags.top \u786E\u8BA4\u540E\u53EF\u4E00\u952E\u8FD4\u56DE\u81EA\u52A8\u9A8C\u8BC1\uFF0C\u6216\u590D\u5236 6 \u4F4D\u6570\u5B57\u7801\u586B\u5230\u4E0B\u65B9',
        verifyBtn: '\u9A8C\u8BC1\u8EAB\u4EFD',
        allowUsersLabel: '\u5141\u8BB8\u4F7F\u7528\u7684 xtags \u7528\u6237 ID \u767D\u540D\u5355\uFF08\u9017\u53F7\u5206\u9694\uFF0C\u9ED8\u8BA4\u4EC5\u4F60\u672C\u4EBA\uFF09',
        staticTokenLabel: '2. \u8BBE\u7F6E\u9759\u6001\u8BBF\u95EE\u4EE4\u724C\uFF08\u540C\u65F6\u7528\u4E8E\u7BA1\u7406\u5458\u767B\u5F55\uFF09',
        genRandomBtn: '\u968F\u673A\u751F\u6210',
        advancedOptions: '\u9AD8\u7EA7\u53C2\u6570\uFF08\u4E2D\u7EE7\u540D\u79F0 / \u914D\u989D / \u81EA\u5B9A\u4E49 Auth API\uFF09',
        siteNameLabel: '\u4E2D\u7EE7\u540D\u79F0',
        maxEnvLabel: '\u6BCF\u7EC4\u4FDD\u7559\u526A\u8D34\u677F\u6761\u6570',
        maxBlobLabel: '\u5355\u6587\u4EF6\u6700\u5927\u4F53\u79EF (MB)',
        blobTTLLabel: '\u52A0\u5BC6\u6587\u4EF6\u4FDD\u7559\u5929\u6570',
        adminTokenOptLabel: '\u66F4\u65B0\u53D1\u5E03 Admin Token\uFF08\u53EF\u9009\uFF09',
        completeSetupBtn: '\u5B8C\u6210\u521D\u59CB\u5316\u5E76\u4FDD\u5B58\u914D\u7F6E',
        saveEditBtn: '\u4FDD\u5B58\u914D\u7F6E\u66F4\u6539',
        cancelBtn: '\u53D6\u6D88',
        readyTitle: '\u4E2D\u7EE7\u5DF2\u5C31\u7EEA\uFF0C\u53EF\u7ACB\u5373\u5728 SyncNow \u4E2D\u63A5\u5165',
        readyDesc: '\u6240\u6709\u526A\u8D34\u677F\u4E0E\u6587\u4EF6\u5747\u7531\u5BA2\u6237\u7AEF ChaCha20-Poly1305 \u7AEF\u5230\u7AEF\u52A0\u5BC6\uFF0C\u670D\u52A1\u7AEF\u5168\u7A0B\u96F6\u660E\u6587\u3002',
        checkUpdateBtn: '\u68C0\u67E5\u5347\u7EA7',
        checkingUpdateBtn: '\u68C0\u6D4B\u4E2D\u2026',
        closeBtn: '\u6536\u8D77',
        manageConfigBtn: '\u7BA1\u7406\u914D\u7F6E',
        lockSessionBtn: '\u9501\u5B9A\u9000\u51FA',
        kvRelayURL: '\u81EA\u5EFA\u4E2D\u7EE7\u5730\u5740',
        kvAuthMode: '\u9274\u6743\u6A21\u5F0F',
        kvOwner: '\u7ED1\u5B9A\u673A\u4E3B',
        kvQuota: '\u5B58\u50A8\u914D\u989D',
        clientConnectLabel: '\u5728 SyncNow \u5BA2\u6237\u7AEF\u63A5\u5165\uFF08\u6253\u5F00\u300Cxtags.top \u7EDF\u4E00\u8D26\u53F7\u4E0E\u81EA\u5EFA\u4E2D\u7EE7\u300D\u7C98\u8D34\u4E0B\u65B9\u5730\u5740\uFF09',
        copyUrlBtn: '\u590D\u5236\u5730\u5740',
        copied: '\u5DF2\u590D\u5236 \u2713',
        testHealthBtn: '\u8FDE\u901A\u6D4B\u8BD5',
        adminLoginTitle: '\u6B64\u4E2D\u7EE7\u5DF2\u542F\u7528\u8BBF\u95EE\u4FDD\u62A4',
        adminLoginDesc: '\u9ED8\u8BA4\u7981\u6B62\u672A\u6388\u6743\u8BBF\u95EE\u3002\u8BF7\u8F93\u5165\u673A\u4E3B xtags.top 6 \u4F4D\u6388\u6743\u7801\u3001\u4EE4\u724C\u6216\u9759\u6001\u7BA1\u7406\u4EE4\u724C\u4EE5\u89E3\u9501\u7BA1\u7406\u63A7\u5236\u53F0\u3002',
        unlockBtn: '\u9A8C\u8BC1\u5E76\u89E3\u9501',
        onlinePeersTitle: '\u5F53\u524D\u540C\u8D26\u53F7\u5728\u7EBF\u4FE1\u4EE4\u8BBE\u5907',
        onlinePeersDesc: '\u901A\u8FC7 /v1/signal/ws \u5DF2\u8FDE\u63A5\u81F3\u6B64\u4E2D\u7EE7\u7684\u540C\u8D26\u53F7\u8BBE\u5907\u5217\u8868',
        refreshBtn: '\u5237\u65B0',
        resetBtn: '\u91CD\u7F6E\u521D\u59CB\u5316',
        statusReady: '\u8FD0\u884C\u6B63\u5E38',
        statusPending: '\u5F85\u521D\u59CB\u5316',
        statusProtected: '\u53D7\u4FDD\u62A4 \xB7 \u9700\u9274\u6743',
      },
      en: {
        setupTitle: 'Set Up Your SyncNow Relay',
        setupDesc: 'Installation succeeded! Configure owner binding and security policy right here in 30 seconds\u2014no env editing required.',
        chooseMode: '1. Choose Authentication & Access Policy',
        modeOwnerTitle: 'xtags Owner-Only (Recommended)',
        modeOwnerDesc: 'Bind your xtags.top account so only you (or your allowlist) can use this relay with zero-pairing control.',
        modeMultiTitle: 'xtags Multi-Account Isolated',
        modeMultiDesc: 'Allow any valid xtags.top account with strict per-userId room isolation; binds you as relay admin.',
        modeStaticTitle: 'Offline Static Token',
        modeStaticDesc: 'Airgapped mode without xtags.top; all devices share one static Bearer token.',
        xtagsVerifyLabel: '2. Verify Owner via xtags.top (One-Click Relay Auth or 6-Digit Code)',
        getSixDigitCode: 'Authorize on xtags.top & Get 6-Digit Code \u2197',
        xtagsCodeHint: 'Confirm on xtags.top to return & verify automatically, or paste the 6-digit code below',
        verifyBtn: 'Verify',
        allowUsersLabel: 'Allowed xtags User IDs (comma-separated, defaults to owner)',
        staticTokenLabel: '2. Set Static Access Token (also unlocks Admin Settings)',
        genRandomBtn: 'Generate',
        advancedOptions: 'Advanced Settings (Site Name / Quotas / Custom Auth API)',
        siteNameLabel: 'Relay Name',
        maxEnvLabel: 'Max Retained Envelopes / Group',
        maxBlobLabel: 'Max Encrypted Blob Size (MB)',
        blobTTLLabel: 'Encrypted Blob TTL (Days)',
        adminTokenOptLabel: 'Release Admin Token (Optional)',
        completeSetupBtn: 'Finish Setup & Save',
        saveEditBtn: 'Save Configuration',
        cancelBtn: 'Cancel',
        readyTitle: 'Relay is Ready for SyncNow',
        readyDesc: 'All clipboard items and files are encrypted client-side with ChaCha20-Poly1305. Zero plaintext on server.',
        checkUpdateBtn: 'Check Update',
        checkingUpdateBtn: 'Checking\u2026',
        closeBtn: 'Hide',
        manageConfigBtn: 'Manage Settings',
        lockSessionBtn: 'Lock & Sign Out',
        kvRelayURL: 'Relay URL',
        kvAuthMode: 'Auth Policy',
        kvOwner: 'Bound Owner',
        kvQuota: 'Quotas',
        clientConnectLabel: 'Connect in SyncNow (paste this URL into Account & Self-Hosted Relay)',
        copyUrlBtn: 'Copy URL',
        copied: 'Copied \u2713',
        testHealthBtn: 'Test Health',
        adminLoginTitle: 'Protected Relay \xB7 Authentication Required',
        adminLoginDesc: 'Unauthenticated access is denied by default. Enter the owner xtags.top 6-digit code, access token, or static admin token to unlock.',
        unlockBtn: 'Verify & Unlock',
        onlinePeersTitle: 'Online Same-Account Signaling Peers',
        onlinePeersDesc: 'Devices currently connected via /v1/signal/ws under your account',
        refreshBtn: 'Refresh',
        resetBtn: 'Reset Setup',
        statusReady: 'Ready',
        statusPending: 'Setup Required',
        statusProtected: 'Protected',
      }
    };

    let lang = (navigator.language || '').toLowerCase().startsWith('zh') ? 'zh' : 'en';
    let currentStatus = null;
    let selectedMode = 'xtags_owner';
    let verifiedXTags = null; // { token, user }
    let adminBearer = sessionStorage.getItem('syncnow_relay_admin_token') || '';
    let isEditingExisting = false;
    let relayUpdateInfo = null;
    let relayUpdateAutoChecked = false;

    const $ = (id) => document.getElementById(id);

    function applyLang() {
      const dict = I18N[lang];
      document.querySelectorAll('[data-i18n]').forEach((el) => {
        const key = el.getAttribute('data-i18n');
        if (dict[key]) el.textContent = dict[key];
      });
      $('langBtn').textContent = lang === 'zh' ? 'EN' : '\u4E2D\u6587';
      if (currentStatus) renderStatus({ preserveForm: true });
    }

    function showNotice(el, text, cls) {
      el.className = 'notice ' + cls;
      el.textContent = text;
      el.classList.remove('hidden');
    }

    function selectMode(mode) {
      selectedMode = mode;
      document.querySelectorAll('.mode-card').forEach((c) => {
        c.classList.toggle('active', c.dataset.mode === mode);
      });
      const isStatic = mode === 'static_token';
      $('xtagsAuthPanel').classList.toggle('hidden', isStatic);
      $('staticAuthPanel').classList.toggle('hidden', !isStatic);
      $('allowUsersWrap').classList.toggle('hidden', mode !== 'xtags_owner' || (!verifiedXTags && !isEditingExisting));
    }

    function authModeLabel(mode) {
      if (lang === 'zh') {
        if (mode === 'xtags_owner') return 'xtags.top \u673A\u4E3B\u72EC\u5360\u767D\u540D\u5355';
        if (mode === 'xtags_multi') return 'xtags.top \u591A\u8D26\u53F7\u9694\u79BB';
        return '\u79BB\u7EBF\u9759\u6001\u4EE4\u724C';
      }
      if (mode === 'xtags_owner') return 'xtags.top Owner Allowlist';
      if (mode === 'xtags_multi') return 'xtags.top Multi-Account';
      return 'Offline Static Token';
    }

    async function loadStatus() {
      const headers = {};
      if (adminBearer) headers['Authorization'] = 'Bearer ' + adminBearer;
      const res = await fetch('/v1/setup/status', { headers });
      if (res.status === 401) {
        if (adminBearer) {
          adminBearer = '';
          sessionStorage.removeItem('syncnow_relay_admin_token');
        }
        currentStatus = { initialized: true, isAdmin: false, locked: true };
        renderStatus();
        return;
      }
      currentStatus = await res.json();
      renderStatus();
    }

    function renderStatus(opts = {}) {
      const { preserveForm = false } = opts;
      const s = currentStatus;
      const dict = I18N[lang];

      const pill = $('statusPill');
      if (s.locked || (s.initialized && !s.isAdmin)) {
        isEditingExisting = false;
        $('siteTitle').textContent = 'SyncNow Relay';
        pill.className = 'pill warn';
        $('statusText').textContent = dict.statusProtected;
        $('runtimePill').textContent = '401 \xB7 Auth Required';
        $('setupWizardCard').classList.add('hidden');
        $('overviewCard').classList.add('hidden');
        $('adminPeersCard').classList.add('hidden');
        $('adminAuthCard').classList.remove('hidden');
        $('adminLoginDesc').textContent = dict.adminLoginDesc;
        $('adminCancelBtn').classList.add('hidden');
        $('adminXTagsShortcut').classList.remove('hidden');
        return;
      }

      $('siteTitle').textContent = s.siteName || 'SyncNow Relay';
      const baseRuntime = \`\${s.runtime === 'cloudflare-workers' ? 'Cloudflare Workers' : 'Go Relay'} \xB7 v\${s.version || '0.3.2'}\`;
      $('runtimePill').textContent = relayUpdateInfo?.hasUpdate
        ? \`\${baseRuntime} \xB7 \${lang === 'zh' ? '\u6709\u65B0\u7248' : 'Update'} v\${relayUpdateInfo.latestVersion}\`
        : baseRuntime;
      if (relayUpdateInfo && !$('relayUpdateBox').classList.contains('hidden')) {
        renderRelayUpdatePanel(relayUpdateInfo);
      }

      if (s.initialized) {
        pill.className = 'pill ok';
        $('statusText').textContent = dict.statusReady;
      } else {
        pill.className = 'pill warn';
        $('statusText').textContent = dict.statusPending;
      }

      const origin = window.location.origin;
      $('relayUrlDisplay').textContent = origin;
      $('relayUrlCode').textContent = origin;
      $('authModeDisplay').textContent = authModeLabel(s.authMode);
      $('ownerDisplay').textContent = s.ownerDisplayName
        ? \`\${s.ownerDisplayName} (\${s.ownerUserID || ''})\`
        : (s.authMode === 'static_token' ? 'Static Token' : (s.ownerLocked ? \`\${s.allowUsersCount} allowed\` : 'Any valid xtags user'));
      $('quotaDisplay').textContent = \`\${s.maxEnvelopes} items \xB7 \${s.maxBlobMB}MB/file \xB7 \${s.blobTTLDays}d TTL\${s.r2Enabled ? ' \xB7 R2' : ''}\`;

      if (!s.initialized) {
        isEditingExisting = false;
        $('setupWizardCard').classList.remove('hidden');
        $('overviewCard').classList.add('hidden');
        $('adminAuthCard').classList.add('hidden');
        $('adminPeersCard').classList.add('hidden');
        $('cancelEditBtn').classList.add('hidden');
        $('completeSetupBtn').textContent = dict.completeSetupBtn;
        if (!preserveForm) populateFormFromStatus(s);
      } else if (isEditingExisting && s.isAdmin) {
        $('setupWizardCard').classList.remove('hidden');
        $('overviewCard').classList.remove('hidden');
        $('adminAuthCard').classList.add('hidden');
        $('adminPeersCard').classList.remove('hidden');
        $('cancelEditBtn').classList.remove('hidden');
        $('completeSetupBtn').textContent = dict.saveEditBtn;
        if (!preserveForm) populateFormFromStatus(s);
        void loadOnlinePeers();
      } else {
        $('setupWizardCard').classList.add('hidden');
        $('overviewCard').classList.remove('hidden');
        $('adminAuthCard').classList.add('hidden');
        $('adminPeersCard').classList.toggle('hidden', !s.isAdmin);
        if (s.isAdmin) {
          void loadOnlinePeers();
          if (!relayUpdateAutoChecked) {
            relayUpdateAutoChecked = true;
            void checkRelayUpdate(false);
          }
        }
      }
    }

    function populateFormFromStatus(s) {
      selectMode(s.authMode || 'xtags_owner');
      $('setupSiteName').value = s.siteName || 'SyncNow Relay';
      $('setupAuthAPI').value = s.authAPI || 'https://api.xtags.top';
      $('setupMaxEnvelopes').value = s.maxEnvelopes || 500;
      $('setupMaxBlobMB').value = s.maxBlobMB || 25;
      $('setupBlobTTLDays').value = s.blobTTLDays || 7;
      $('setupAllowUsers').value = Array.isArray(s.allowUsers) ? s.allowUsers.join(', ') : '';
      if (s.ownerUserID && !verifiedXTags) {
        const label = s.ownerDisplayName ? \`\${s.ownerDisplayName} (\${s.ownerUserID})\` : s.ownerUserID;
        showNotice($('verifiedUserBox'), \`\u5DF2\u7ED1\u5B9A\u673A\u4E3B\uFF1A\${label}\`, 'ok');
      }
    }

    async function verifyXTagsCredential(rawVal, authAPI) {
      const cleaned = rawVal.trim();
      const digits = cleaned.replace(/[\\s-]+/g, '');
      const payload = /^\\d{6}$/.test(digits)
        ? { authCode: digits, authAPI }
        : { token: cleaned, authAPI };
      const res = await fetch('/v1/setup/verify-xtags', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.message || data.error || \`HTTP \${res.status}\`);
      return data;
    }

    async function loadOnlinePeers() {
      if (!adminBearer) return;
      try {
        const res = await fetch('/v1/signal/peers', {
          headers: { Authorization: 'Bearer ' + adminBearer }
        });
        if (!res.ok) {
          $('peersListBox').textContent = lang === 'zh' ? '\u5F53\u524D\u51ED\u8BC1\u65E0\u6CD5\u8BFB\u53D6\u4FE1\u4EE4\u5217\u8868' : 'Unable to fetch signaling peers';
          return;
        }
        const data = await res.json();
        const peers = data.peers || [];
        if (peers.length === 0) {
          $('peersListBox').textContent = lang === 'zh'
            ? '\u6682\u65E0\u8BBE\u5907\u8FDE\u63A5\u5230\u6B64\u4E2D\u7EE7\u4FE1\u4EE4\uFF08\u5728 SyncNow \u5BA2\u6237\u7AEF\u542F\u7528\u6B64\u81EA\u5EFA\u4E2D\u7EE7\u540E\u5C06\u5B9E\u65F6\u663E\u793A\uFF09'
            : 'No devices connected to signaling yet.';
          return;
        }
        $('peersListBox').innerHTML = peers.map((p) => {
          const eps = (p.lanEndpoints || []).map((e) => \`\${e.host}:\${e.tcpPort}\`).join(', ');
          return \`<div class="kv" style="margin-bottom:8px;">
            <div class="v">\${escapeHtml(p.deviceName || p.deviceID)} <span style="color:var(--ok);font-size:11px;">\u25CF Online</span></div>
            <div class="k" style="text-transform:none;margin-top:3px;">\${escapeHtml(p.platform || '')} \xB7 \${escapeHtml(eps || p.observedPublicIP || 'Relay')}</div>
          </div>\`;
        }).join('');
      } catch {
        $('peersListBox').textContent = '-';
      }
    }

    function escapeHtml(s) {
      return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
    }

    function randomTokenHex(bytes = 24) {
      const arr = new Uint8Array(bytes);
      crypto.getRandomValues(arr);
      return 'snr_' + Array.from(arr, (b) => b.toString(16).padStart(2, '0')).join('');
    }

    // Event wiring
    $('langBtn').addEventListener('click', () => {
      lang = lang === 'zh' ? 'en' : 'zh';
      applyLang();
    });

    document.querySelectorAll('.mode-card').forEach((btn) => {
      btn.addEventListener('click', () => selectMode(btn.dataset.mode));
    });

    $('genStaticTokenBtn').addEventListener('click', () => {
      $('setupStaticToken').value = randomTokenHex(24);
    });

    async function copyTextSafe(text) {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text);
        return;
      }
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.setAttribute('readonly', '');
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
    }

    function syncRelayAuthLinks() {
      const relaySetupUrl = window.location.origin + '/setup';
      const authUrl = 'https://xtags.top/auth/extension?client=syncnow&mode=code&relay=' + encodeURIComponent(relaySetupUrl);
      const setupLink = $('openXTagsCodeBtn');
      const adminLink = $('adminXTagsCodeBtn');
      if (setupLink) setupLink.href = authUrl;
      if (adminLink) adminLink.href = authUrl;
    }

    function consumeIncomingAuthCode() {
      const rawHash = (window.location.hash || '').replace(/^#/, '');
      if (!rawHash) return '';
      const params = new URLSearchParams(rawHash);
      const code = (params.get('authCode') || params.get('code') || '').replace(/[\\s-]+/g, '').trim();
      if (/^\\d{6}$/.test(code)) {
        try {
          window.history.replaceState(null, '', window.location.pathname + window.location.search);
        } catch {}
        return code;
      }
      return '';
    }

    async function runSetupVerify(rawInput) {
      const raw = (rawInput || '').trim();
      if (!raw) return;
      $('verifyXTagsBtn').disabled = true;
      $('setupMsg').classList.add('hidden');
      try {
        const res = await verifyXTagsCredential(raw, $('setupAuthAPI').value.trim() || 'https://api.xtags.top');
        verifiedXTags = res;
        showNotice($('verifiedUserBox'), \`\u2713 \u5DF2\u9A8C\u8BC1 xtags.top \u8D26\u53F7\uFF1A\${res.user.displayName} (\${res.user.id})\`, 'ok');
        if (!$('setupAllowUsers').value.trim()) {
          $('setupAllowUsers').value = res.user.id;
        }
        if (selectedMode === 'xtags_owner') {
          $('allowUsersWrap').classList.remove('hidden');
        }
      } catch (err) {
        verifiedXTags = null;
        showNotice($('setupMsg'), err.message || String(err), 'err');
      } finally {
        $('verifyXTagsBtn').disabled = false;
      }
    }

    async function runAdminUnlock(rawInput) {
      const raw = (rawInput || '').trim();
      if (!raw) return;
      $('adminUnlockBtn').disabled = true;
      $('adminAuthMsg').classList.add('hidden');
      try {
        let tokenToUse = raw;
        const digits = raw.replace(/[\\s-]+/g, '');
        if (/^\\d{6}$/.test(digits)) {
          const v = await verifyXTagsCredential(digits, currentStatus?.authAPI || 'https://api.xtags.top');
          tokenToUse = v.token;
        }
        const res = await fetch('/v1/setup/status', {
          headers: { Authorization: 'Bearer ' + tokenToUse },
        });
        const st = await res.json().catch(() => ({}));
        if (!res.ok || !st.isAdmin) {
          throw new Error(lang === 'zh' ? '\u8BE5\u8D26\u53F7\u6216\u4EE4\u724C\u4E0D\u662F\u6B64\u4E2D\u7EE7\u7684\u7BA1\u7406\u5458/\u673A\u4E3B' : 'Not authorized as relay administrator');
        }
        const wasLocked = Boolean(currentStatus?.locked);
        adminBearer = tokenToUse;
        sessionStorage.setItem('syncnow_relay_admin_token', adminBearer);
        currentStatus = st;
        isEditingExisting = !wasLocked;
        $('adminTokenInput').value = '';
        renderStatus();
      } catch (err) {
        showNotice($('adminAuthMsg'), err.message || String(err), 'err');
      } finally {
        $('adminUnlockBtn').disabled = false;
      }
    }

    $('openXTagsCodeBtn').addEventListener('click', () => {
      try {
        sessionStorage.setItem('syncnow_setup_pending_mode', selectedMode);
      } catch {}
    });

    $('verifyXTagsBtn').addEventListener('click', () => void runSetupVerify($('setupXTagsInput').value));
    $('setupXTagsInput').addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        void runSetupVerify($('setupXTagsInput').value);
      }
    });

    $('completeSetupBtn').addEventListener('click', async () => {
      $('completeSetupBtn').disabled = true;
      $('setupMsg').classList.add('hidden');
      try {
        const authAPI = $('setupAuthAPI').value.trim() || 'https://api.xtags.top';
        let xtagsToken = selectedMode === 'static_token' ? '' : (verifiedXTags?.token || '');
        const rawInput = $('setupXTagsInput').value.trim();

        if (selectedMode !== 'static_token' && !xtagsToken && rawInput) {
          const v = await verifyXTagsCredential(rawInput, authAPI);
          verifiedXTags = v;
          xtagsToken = v.token;
          if (!$('setupAllowUsers').value.trim()) $('setupAllowUsers').value = v.user.id;
        }

        if (selectedMode !== 'static_token' && !currentStatus.initialized && !xtagsToken) {
          throw new Error(lang === 'zh' ? '\u8BF7\u5148\u8F93\u5165 xtags.top 6 \u4F4D\u6388\u6743\u7801\u6216\u4EE4\u724C\u5B8C\u6210\u673A\u4E3B\u9A8C\u8BC1' : 'Please verify your xtags.top 6-digit code or token first');
        }

        const staticToken = $('setupStaticToken').value.trim();
        if (selectedMode === 'static_token' && !currentStatus.initialized && staticToken.length < 12) {
          throw new Error(lang === 'zh' ? '\u9759\u6001\u4EE4\u724C\u81F3\u5C11\u9700\u8981 12 \u4F4D\u5B57\u7B26\uFF08\u53EF\u70B9\u51FB\u201C\u968F\u673A\u751F\u6210\u201D\uFF09' : 'Static token must be at least 12 characters');
        }

        const allowUsers = $('setupAllowUsers').value
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean);

        const body = {
          siteName: $('setupSiteName').value.trim() || 'SyncNow Relay',
          authMode: selectedMode,
          authAPI: selectedMode === 'static_token' ? '' : authAPI,
          xtagsToken: selectedMode === 'static_token' ? undefined : (xtagsToken || undefined),
          allowUsers: selectedMode === 'xtags_owner' ? allowUsers : [],
          staticToken: selectedMode === 'static_token' ? staticToken : '',
          adminToken: $('setupAdminToken').value.trim() || undefined,
          maxEnvelopes: Number($('setupMaxEnvelopes').value) || 500,
          maxBlobMB: Number($('setupMaxBlobMB').value) || 25,
          blobTTLDays: Number($('setupBlobTTLDays').value) || 7,
        };

        const headers = { 'Content-Type': 'application/json' };
        if (adminBearer) headers['Authorization'] = 'Bearer ' + adminBearer;
        else if (xtagsToken) headers['Authorization'] = 'Bearer ' + xtagsToken;

        const res = await fetch('/v1/setup/complete', {
          method: 'POST',
          headers,
          body: JSON.stringify(body),
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(data.message || data.error || \`HTTP \${res.status}\`);

        if (selectedMode === 'static_token') {
          verifiedXTags = null;
          if (staticToken) {
            adminBearer = staticToken;
            sessionStorage.setItem('syncnow_relay_admin_token', adminBearer);
          }
        } else if (xtagsToken) {
          adminBearer = xtagsToken;
          sessionStorage.setItem('syncnow_relay_admin_token', adminBearer);
        }

        isEditingExisting = false;
        await loadStatus();
        showNotice($('overviewNotice'), lang === 'zh' ? '\u2713 \u914D\u7F6E\u5DF2\u4FDD\u5B58\u5E76\u5B9E\u65F6\u751F\u6548\uFF01' : '\u2713 Configuration saved and live!', 'ok');
      } catch (err) {
        showNotice($('setupMsg'), err.message || String(err), 'err');
      } finally {
        $('completeSetupBtn').disabled = false;
      }
    });

    $('openAdminLoginBtn').addEventListener('click', () => {
      if (currentStatus?.isAdmin) {
        isEditingExisting = true;
        renderStatus();
        return;
      }
      $('adminAuthCard').classList.remove('hidden');
      $('adminXTagsShortcut').classList.toggle('hidden', currentStatus?.authMode === 'static_token');
      $('adminTokenInput').focus();
    });

    $('adminCancelBtn').addEventListener('click', () => {
      $('adminAuthCard').classList.add('hidden');
    });

    $('cancelEditBtn').addEventListener('click', () => {
      isEditingExisting = false;
      renderStatus();
    });

    $('adminLogoutBtn').addEventListener('click', async () => {
      adminBearer = '';
      verifiedXTags = null;
      isEditingExisting = false;
      relayUpdateInfo = null;
      relayUpdateAutoChecked = false;
      $('relayUpdateBox').classList.add('hidden');
      sessionStorage.removeItem('syncnow_relay_admin_token');
      await loadStatus();
    });

    $('adminUnlockBtn').addEventListener('click', () => void runAdminUnlock($('adminTokenInput').value));
    $('adminTokenInput').addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        void runAdminUnlock($('adminTokenInput').value);
      }
    });

    $('copyUrlBtn').addEventListener('click', async () => {
      await copyTextSafe(window.location.origin);
      $('copyUrlBtn').textContent = I18N[lang].copied;
      setTimeout(() => { $('copyUrlBtn').textContent = I18N[lang].copyUrlBtn; }, 1800);
    });

    $('testHealthBtn').addEventListener('click', async () => {
      const t0 = performance.now();
      try {
        const headers = adminBearer ? { Authorization: 'Bearer ' + adminBearer } : {};
        const res = await fetch('/health', { headers });
        const ms = Math.max(1, Math.round(performance.now() - t0));
        const body = await res.json().catch(() => ({}));
        if (res.ok) {
          showNotice($('overviewNotice'), \`\u2713 /health OK (\${ms}ms) \xB7 \${JSON.stringify(body.capabilities || [])}\`, 'ok');
        } else {
          showNotice($('overviewNotice'), \`HTTP \${res.status}: \${body.message || 'error'}\`, 'err');
        }
      } catch (err) {
        showNotice($('overviewNotice'), err.message || String(err), 'err');
      }
    });

    function inferWorkerName() {
      const host = (window.location.hostname || '').toLowerCase();
      if (host.endsWith('.workers.dev')) {
        const parts = host.split('.');
        if (parts.length >= 4 && parts[0]) return parts[0];
      }
      return 'syncnow-relay';
    }

    function renderRelayUpdatePanel(info) {
      const box = $('relayUpdateBox');
      const titleEl = $('relayUpdateTitle');
      const descEl = $('relayUpdateDesc');
      const webBtn = $('relayUpgradeWebBtn');
      const cmdsEl = $('relayUpgradeCmds');
      const isCF = (info.runtime || currentStatus?.runtime) === 'cloudflare-workers';
      const curVer = info.currentVersion || currentStatus?.version || '0.3.2';
      const latestVer = info.latestVersion || curVer;

      if (info.hasUpdate) {
        box.style.borderColor = 'rgba(245, 158, 11, 0.45)';
        titleEl.style.color = 'var(--warn)';
        titleEl.textContent = lang === 'zh'
          ? \`\u53D1\u73B0\u4E2D\u7EE7\u65B0\u7248\u672C\uFF1Av\${curVer} \u2192 v\${latestVer}\`
          : \`Relay Update Available: v\${curVer} \u2192 v\${latestVer}\`;
        descEl.textContent = lang === 'zh'
          ? '\u5347\u7EA7\u8FC7\u7A0B\u4FDD\u7559\u5168\u90E8\u673A\u4E3B\u7ED1\u5B9A\u3001\u767D\u540D\u5355\u4E0E\u52A0\u5BC6\u5386\u53F2\u6570\u636E\uFF0C\u65E0\u9700\u91CD\u65B0\u521D\u59CB\u5316\u3002'
          : 'Upgrading preserves your owner binding, allowlist, and encrypted data in-place.';
      } else if (info.checkError) {
        box.style.borderColor = 'var(--border)';
        titleEl.style.color = 'var(--text)';
        titleEl.textContent = lang === 'zh'
          ? \`\u5F53\u524D\u7248\u672C v\${curVer}\uFF08\u6682\u65E0\u6CD5\u5728\u7EBF\u68C0\u6D4B\u6700\u65B0\u7248\u672C\uFF09\`
          : \`Current version v\${curVer} (unable to check online)\`;
        descEl.textContent = lang === 'zh'
          ? '\u4ECD\u53EF\u4F7F\u7528\u4E0B\u65B9\u65B9\u5F0F\u624B\u52A8\u65E0\u635F\u8986\u76D6\u5347\u7EA7\u81F3\u6700\u65B0\u7248\uFF08\u4FDD\u7559\u6240\u6709\u914D\u7F6E\u4E0E\u6570\u636E\uFF09\u3002'
          : 'You can still trigger an in-place upgrade below without losing data.';
      } else {
        box.style.borderColor = 'rgba(34, 197, 94, 0.35)';
        titleEl.style.color = 'var(--ok)';
        titleEl.textContent = lang === 'zh'
          ? \`\u2713 \u5F53\u524D\u4E2D\u7EE7\u5DF2\u662F\u6700\u65B0\u7248\u672C (v\${curVer})\`
          : \`\u2713 Relay is up to date (v\${curVer})\`;
        descEl.textContent = lang === 'zh'
          ? '\u5982\u9700\u91CD\u65B0\u62C9\u53D6\u6700\u65B0\u6784\u5EFA\u6216\u5F3A\u5236\u8986\u76D6\u90E8\u7F72\uFF0C\u53EF\u76F4\u63A5\u4F7F\u7528\u4E0B\u65B9\u65E0\u635F\u5347\u7EA7\u5165\u53E3\u3002'
          : 'Need to re-deploy or force-refresh the latest build? Use the in-place upgrade options below.';
      }

      const cmds = [];
      if (isCF) {
        const worker = inferWorkerName();
        const deployBase = info.deployUrl || 'https://xtags.top/deploy/syncnow';
        webBtn.href = \`\${deployBase}?mode=upgrade&worker=\${encodeURIComponent(worker)}&relay=\${encodeURIComponent(window.location.origin)}\`;
        webBtn.textContent = info.hasUpdate
          ? (lang === 'zh' ? '\u524D\u5F80\u4E00\u952E\u65E0\u635F\u5347\u7EA7 \u2197' : '1-Click Upgrade on xtags.top \u2197')
          : (lang === 'zh' ? '\u524D\u5F80\u91CD\u65B0\u90E8\u7F72 / \u5347\u7EA7 \u2197' : 'Re-deploy / Upgrade \u2197');
        webBtn.classList.remove('hidden');
        const cfCmd = worker === 'syncnow-relay'
          ? 'curl -fsSL https://raw.githubusercontent.com/zsai001/syncnow/main/deploy/cf-deploy.sh | bash'
          : \`curl -fsSL https://raw.githubusercontent.com/zsai001/syncnow/main/deploy/cf-deploy.sh | WORKER_NAME=\${worker} bash\`;
        cmds.push({
          label: lang === 'zh' ? '\u6216\u672C\u5730\u7EC8\u7AEF\u4E00\u884C\u65E0\u635F\u5347\u7EA7\uFF08Cloudflare CLI\uFF09' : 'Or upgrade via terminal (Cloudflare CLI)',
          cmd: cfCmd,
        });
      } else {
        webBtn.classList.add('hidden');
        cmds.push({
          label: lang === 'zh' ? 'Linux VPS \u4E00\u884C\u65E0\u635F\u5347\u7EA7\uFF08\u4FDD\u7559\u914D\u7F6E\u4E0E\u6570\u636E\uFF09' : 'Linux VPS 1-Line In-Place Upgrade',
          cmd: info.vpsUpgradeCmd || 'curl -fsSL https://raw.githubusercontent.com/zsai001/syncnow/main/deploy/vps-install.sh | sudo bash',
        });
        cmds.push({
          label: lang === 'zh' ? 'Docker Compose \u5347\u7EA7\uFF08\u4FDD\u7559\u6570\u636E\u5377\uFF09' : 'Docker Compose Upgrade (Preserves Volume)',
          cmd: info.dockerUpgradeCmd || 'git pull && docker compose up -d --build',
        });
      }

      cmdsEl.innerHTML = cmds.map((item, idx) => \`
        <div>
          <div style="font-size:11px; color:var(--muted); margin-bottom:4px;">\${escapeHtml(item.label)}</div>
          <div class="row">
            <div class="code-box" style="flex:1; padding:8px 10px; font-size:11.5px;">\${escapeHtml(item.cmd)}</div>
            <button type="button" class="btn sm" data-upgrade-copy="\${idx}">\${lang === 'zh' ? '\u590D\u5236' : 'Copy'}</button>
          </div>
        </div>
      \`).join('');

      cmdsEl.querySelectorAll('[data-upgrade-copy]').forEach((btn) => {
        btn.addEventListener('click', async () => {
          const idx = Number(btn.getAttribute('data-upgrade-copy'));
          const target = cmds[idx];
          if (!target) return;
          await copyTextSafe(target.cmd);
          const orig = btn.textContent;
          btn.textContent = I18N[lang].copied;
          setTimeout(() => { btn.textContent = orig; }, 1600);
        });
      });

      box.classList.remove('hidden');
    }

    async function checkRelayUpdate(showAlways = true) {
      const btn = $('checkRelayUpdateBtn');
      if (btn && showAlways) {
        btn.disabled = true;
        btn.textContent = I18N[lang].checkingUpdateBtn;
      }
      try {
        const headers = adminBearer ? { Authorization: 'Bearer ' + adminBearer } : {};
        const res = await fetch('/v1/setup/relay-update', { headers });
        if (!res.ok) {
          if (showAlways) {
            showNotice($('overviewNotice'), \`HTTP \${res.status}\`, 'err');
          }
          return;
        }
        relayUpdateInfo = await res.json();
        const baseRuntime = \`\${currentStatus?.runtime === 'cloudflare-workers' ? 'Cloudflare Workers' : 'Go Relay'} \xB7 v\${currentStatus?.version || '0.3.2'}\`;
        $('runtimePill').textContent = relayUpdateInfo.hasUpdate
          ? \`\${baseRuntime} \xB7 \${lang === 'zh' ? '\u6709\u65B0\u7248' : 'Update'} v\${relayUpdateInfo.latestVersion}\`
          : baseRuntime;
        if (showAlways || relayUpdateInfo.hasUpdate) {
          renderRelayUpdatePanel(relayUpdateInfo);
        }
      } catch (err) {
        if (showAlways) {
          showNotice($('overviewNotice'), err.message || String(err), 'err');
        }
      } finally {
        if (btn) {
          btn.disabled = false;
          btn.textContent = I18N[lang].checkUpdateBtn;
        }
      }
    }

    $('checkRelayUpdateBtn').addEventListener('click', () => void checkRelayUpdate(true));
    $('closeRelayUpdateBtn').addEventListener('click', () => $('relayUpdateBox').classList.add('hidden'));

    $('refreshPeersBtn').addEventListener('click', () => void loadOnlinePeers());

    $('resetSetupBtn').addEventListener('click', async () => {
      if (!confirm(lang === 'zh' ? '\u786E\u5B9A\u8981\u91CD\u7F6E\u9875\u9762\u914D\u7F6E\u5E76\u56DE\u5230\u521D\u59CB Setup \u5411\u5BFC\u5417\uFF1F' : 'Reset web setup configuration?')) return;
      const res = await fetch('/v1/setup/reset', {
        method: 'POST',
        headers: { Authorization: 'Bearer ' + adminBearer },
      });
      if (res.ok) {
        verifiedXTags = null;
        isEditingExisting = false;
        adminBearer = '';
        sessionStorage.removeItem('syncnow_relay_admin_token');
        await loadStatus();
      } else {
        const data = await res.json().catch(() => ({}));
        showNotice($('overviewNotice'), data.message || \`HTTP \${res.status}\`, 'err');
      }
    });

    if ($('brandLogo') && $('appFavicon')) $('brandLogo').src = $('appFavicon').href;
    syncRelayAuthLinks();
    applyLang();
    const incomingAuthCode = consumeIncomingAuthCode();
    loadStatus().then(async () => {
      if (!incomingAuthCode || !currentStatus) return;
      if (!currentStatus.initialized) {
        try {
          const pendingMode = sessionStorage.getItem('syncnow_setup_pending_mode');
          sessionStorage.removeItem('syncnow_setup_pending_mode');
          if (pendingMode === 'xtags_owner' || pendingMode === 'xtags_multi') {
            selectMode(pendingMode);
          }
        } catch {}
        if (selectedMode === 'static_token') selectMode('xtags_owner');
        $('setupXTagsInput').value = incomingAuthCode;
        await runSetupVerify(incomingAuthCode);
      } else if (currentStatus.locked || !currentStatus.isAdmin) {
        $('adminTokenInput').value = incomingAuthCode;
        await runAdminUnlock(incomingAuthCode);
      }
    }).catch((err) => {
      $('statusText').textContent = 'Error';
      console.error(err);
    });
  <\/script>
</body>
</html>
`;

// cloudflare/src/objects.ts
import { DurableObject } from "cloudflare:workers";
var CHUNK_SIZE_BYTES = 1024 * 1024;
var RelayGroupDO = class extends DurableObject {
  static {
    __name(this, "RelayGroupDO");
  }
  initialized = false;
  dynMaxEnvelopes = null;
  dynMaxBlobMB = null;
  dynBlobTTLDays = null;
  ensureSchema() {
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
  applyQuotaHeaders(request) {
    const maxEnv = Number(request.headers.get("X-SyncNow-Max-Envelopes") || "");
    if (Number.isFinite(maxEnv) && maxEnv > 0 && maxEnv <= 5e3) {
      this.dynMaxEnvelopes = maxEnv;
    }
    const maxBlob = Number(request.headers.get("X-SyncNow-Max-Blob-MB") || "");
    if (Number.isFinite(maxBlob) && maxBlob > 0 && maxBlob <= 512) {
      this.dynMaxBlobMB = maxBlob;
    }
    const ttlDays = Number(request.headers.get("X-SyncNow-Blob-TTL-Days") || "");
    if (Number.isFinite(ttlDays) && ttlDays > 0 && ttlDays <= 365) {
      if (this.dynBlobTTLDays !== ttlDays) {
        this.dynBlobTTLDays = ttlDays;
        this.ctx.storage.sql.exec(
          "INSERT OR REPLACE INTO group_meta (key, val) VALUES (?, ?)",
          "blob_ttl_days",
          String(ttlDays)
        );
      }
    }
  }
  maxEnvelopes() {
    if (this.dynMaxEnvelopes !== null) return this.dynMaxEnvelopes;
    const n = Number(this.env.SYNCNOW_MAX_ENVELOPES || "500");
    return Number.isFinite(n) && n > 0 ? Math.min(n, 5e3) : 500;
  }
  maxBlobBytes() {
    if (this.dynMaxBlobMB !== null) return this.dynMaxBlobMB * 1024 * 1024;
    const mb = Number(this.env.SYNCNOW_MAX_BLOB_MB || "25");
    return (Number.isFinite(mb) && mb > 0 ? mb : 25) * 1024 * 1024;
  }
  blobTTLMs() {
    if (this.dynBlobTTLDays !== null) return this.dynBlobTTLDays * 24 * 60 * 60 * 1e3;
    const row = this.ctx.storage.sql.exec("SELECT val FROM group_meta WHERE key = ?", "blob_ttl_days").toArray()[0];
    if (row) {
      const persisted = Number(row.val);
      if (Number.isFinite(persisted) && persisted > 0) {
        this.dynBlobTTLDays = persisted;
        return persisted * 24 * 60 * 60 * 1e3;
      }
    }
    const days = Number(this.env.SYNCNOW_BLOB_TTL_DAYS || "7");
    return (Number.isFinite(days) && days > 0 ? days : 7) * 24 * 60 * 60 * 1e3;
  }
  async fetch(request) {
    this.ensureSchema();
    this.applyQuotaHeaders(request);
    const url = new URL(request.url);
    if (url.pathname === "/ws") {
      return this.handleWebSocket(request, url);
    }
    if (url.pathname === "/v1/push" && request.method === "POST") {
      return this.handlePush(request);
    }
    if (url.pathname === "/v1/sync" && request.method === "GET") {
      return this.handleSync(url);
    }
    if (url.pathname.startsWith("/v1/blobs/")) {
      return this.handleBlob(request, url);
    }
    return apiError(404, "not_found", "Not found");
  }
  handleWebSocket(request, url) {
    if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") {
      return apiError(426, "upgrade_required", "Expected Upgrade: websocket");
    }
    const groupHash = url.searchParams.get("group") || "";
    const deviceID = url.searchParams.get("device") || "";
    if (!SAFE_ID_REGEX.test(groupHash) || !SAFE_ID_REGEX.test(deviceID)) {
      return apiError(400, "invalid_params", "invalid group or device");
    }
    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    this.ctx.acceptWebSocket(server, [deviceID]);
    server.serializeAttachment({ groupHash, deviceID });
    return new Response(null, { status: 101, webSocket: client });
  }
  async webSocketMessage(ws, message) {
    this.ensureSchema();
    const meta = ws.deserializeAttachment();
    if (!meta) return;
    const rawText = typeof message === "string" ? message : new TextDecoder().decode(message);
    let env;
    try {
      env = JSON.parse(rawText);
    } catch {
      return;
    }
    if (env.groupHash !== meta.groupHash) return;
    env.senderDeviceID = meta.deviceID;
    const stored = this.appendEnvelope(env);
    this.broadcastEnvelope(meta.deviceID, stored);
  }
  async webSocketClose(ws) {
    try {
      ws.close();
    } catch {
    }
  }
  async handlePush(request) {
    let env;
    try {
      env = await request.json();
    } catch {
      return apiError(400, "invalid_json", "invalid json");
    }
    if (!SAFE_ID_REGEX.test(env.groupHash || "") || !SAFE_ID_REGEX.test(env.senderDeviceID || "")) {
      return apiError(400, "invalid_params", "invalid groupHash or senderDeviceID");
    }
    const stored = this.appendEnvelope(env);
    this.broadcastEnvelope(env.senderDeviceID, stored);
    return jsonResponse(stored);
  }
  handleSync(url) {
    const since = Number(url.searchParams.get("since") || "0") || 0;
    let limit = Number(url.searchParams.get("limit") || "100") || 100;
    if (limit <= 0 || limit > 200) limit = 100;
    const rows = this.ctx.storage.sql.exec(
      `SELECT seq, id, group_hash, sender_device_id, created_at_ms, ciphertext_base64, blob_id, blob_size
         FROM envelopes WHERE seq > ? ORDER BY seq ASC LIMIT ?`,
      since,
      limit
    ).toArray();
    const envelopes = rows.map((r) => {
      const out = {
        id: r.id,
        seq: r.seq,
        groupHash: r.group_hash,
        senderDeviceID: r.sender_device_id,
        createdAtMs: r.created_at_ms,
        ciphertextBase64: r.ciphertext_base64
      };
      if (r.blob_id) out.blobID = r.blob_id;
      if (r.blob_size !== null && r.blob_size !== void 0) out.blobSize = r.blob_size;
      return out;
    });
    return jsonResponse(envelopes);
  }
  async handleBlob(request, url) {
    const blobID = url.pathname.slice("/v1/blobs/".length);
    const groupHash = url.searchParams.get("group") || "";
    if (!SAFE_ID_REGEX.test(blobID) || !SAFE_ID_REGEX.test(groupHash)) {
      return apiError(400, "invalid_params", "invalid blobID or group");
    }
    const r2Key = `${groupHash}/${blobID}`;
    if (request.method === "POST" || request.method === "PUT") {
      const data = new Uint8Array(await request.arrayBuffer());
      if (data.byteLength > this.maxBlobBytes()) {
        return apiError(413, "blob_too_large", "blob exceeds max allowed size");
      }
      if (this.env.BLOBS) {
        await this.env.BLOBS.put(r2Key, data, {
          httpMetadata: { contentType: "application/octet-stream" },
          customMetadata: { createdAtMs: String(Date.now()) }
        });
        return new Response(null, { status: 201 });
      }
      const now = Date.now();
      this.ctx.storage.sql.exec("DELETE FROM blob_chunks WHERE blob_id = ?", blobID);
      let idx = 0;
      for (let off = 0; off < data.byteLength; off += CHUNK_SIZE_BYTES) {
        const slice = data.subarray(off, Math.min(off + CHUNK_SIZE_BYTES, data.byteLength));
        this.ctx.storage.sql.exec(
          "INSERT INTO blob_chunks (blob_id, chunk_idx, data, created_at_ms) VALUES (?, ?, ?, ?)",
          blobID,
          idx,
          slice,
          now
        );
        idx += 1;
      }
      await this.scheduleBlobCleanupAlarm();
      return new Response(null, { status: 201 });
    }
    if (request.method === "GET") {
      if (this.env.BLOBS) {
        const obj = await this.env.BLOBS.get(r2Key);
        if (!obj) return apiError(404, "not_found", "blob not found");
        return new Response(obj.body, {
          status: 200,
          headers: { "Content-Type": "application/octet-stream" }
        });
      }
      const rows = this.ctx.storage.sql.exec(
        "SELECT data FROM blob_chunks WHERE blob_id = ? ORDER BY chunk_idx ASC",
        blobID
      ).toArray();
      if (rows.length === 0) {
        return apiError(404, "not_found", "blob not found");
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
        headers: { "Content-Type": "application/octet-stream" }
      });
    }
    return apiError(405, "method_not_allowed", "method not allowed");
  }
  async scheduleBlobCleanupAlarm() {
    const existing = await this.ctx.storage.getAlarm();
    if (!existing) {
      await this.ctx.storage.setAlarm(Date.now() + 6 * 60 * 60 * 1e3);
    }
  }
  async alarm() {
    this.ensureSchema();
    const cutoff = Date.now() - this.blobTTLMs();
    this.ctx.storage.sql.exec("DELETE FROM blob_chunks WHERE created_at_ms < ?", cutoff);
    const remaining = this.ctx.storage.sql.exec("SELECT COUNT(*) AS cnt FROM blob_chunks").one();
    if (remaining.cnt > 0) {
      await this.ctx.storage.setAlarm(Date.now() + 6 * 60 * 60 * 1e3);
    }
  }
  appendEnvelope(env) {
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
      env.blobSize ?? null
    );
    const seqRow = this.ctx.storage.sql.exec("SELECT last_insert_rowid() AS seq").one();
    const seq = Number(seqRow.seq);
    const maxKeep = this.maxEnvelopes();
    this.ctx.storage.sql.exec(
      `DELETE FROM envelopes WHERE seq <= (
         SELECT seq FROM envelopes ORDER BY seq DESC LIMIT 1 OFFSET ?
       )`,
      maxKeep
    );
    return {
      ...env,
      seq,
      createdAtMs: now
    };
  }
  broadcastEnvelope(senderDeviceID, env) {
    const payload = JSON.stringify(env);
    for (const sock of this.ctx.getWebSockets()) {
      const meta = sock.deserializeAttachment();
      if (meta?.deviceID === senderDeviceID) continue;
      try {
        sock.send(payload);
      } catch {
        try {
          sock.close();
        } catch {
        }
      }
    }
  }
};
var SignalingRoomDO = class extends DurableObject {
  static {
    __name(this, "SignalingRoomDO");
  }
  async fetch(request) {
    const url = new URL(request.url);
    const userID = request.headers.get("X-SyncNow-Room-ID") || "unknown";
    if (url.pathname === "/v1/signal/ws") {
      if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") {
        return apiError(426, "upgrade_required", "Expected Upgrade: websocket");
      }
      const deviceID = (url.searchParams.get("device") || "").trim();
      if (!SAFE_ID_REGEX.test(deviceID)) {
        return apiError(400, "invalid_device", "valid device query parameter is required");
      }
      for (const existing of this.ctx.getWebSockets(deviceID)) {
        try {
          existing.close(1e3, "Replaced by newer connection");
        } catch {
        }
      }
      const observedIP = request.headers.get("cf-connecting-ip") || request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() || "";
      const pair = new WebSocketPair();
      const [client, server] = Object.values(pair);
      this.ctx.acceptWebSocket(server, [deviceID]);
      const initialAttachment = {
        userID,
        deviceID,
        observedPublicIP: observedIP,
        presence: {
          deviceID,
          deviceName: deviceID,
          platform: "macOS",
          signingPublicKeyBase64: "",
          lanEndpoints: [],
          observedPublicIP: observedIP || void 0,
          tcpPort: 51820,
          udpPort: 0,
          appVersion: "0.1.0",
          online: true,
          updatedAtMs: Date.now()
        }
      };
      server.serializeAttachment(initialAttachment);
      const peers = this.collectOnlinePeers(deviceID);
      const snapshot = {
        type: "peers_snapshot",
        userID,
        peers,
        timeMs: Date.now()
      };
      server.send(JSON.stringify(snapshot));
      return new Response(null, { status: 101, webSocket: client });
    }
    if (url.pathname === "/v1/signal/peers" && request.method === "GET") {
      const exclude = (url.searchParams.get("excludeDevice") || "").trim();
      return jsonResponse({
        userID,
        peers: this.collectOnlinePeers(exclude),
        timeMs: Date.now()
      });
    }
    return apiError(404, "not_found", "Not found");
  }
  async webSocketMessage(ws, message) {
    const att = ws.deserializeAttachment();
    if (!att) return;
    const raw = typeof message === "string" ? message : new TextDecoder().decode(message);
    let msg;
    try {
      msg = JSON.parse(raw);
    } catch {
      return;
    }
    if (msg.type === "register" && msg.presence) {
      const updatedPresence = {
        ...msg.presence,
        deviceID: att.deviceID,
        observedPublicIP: msg.presence.observedPublicIP || att.observedPublicIP || void 0,
        online: true,
        updatedAtMs: Date.now()
      };
      ws.serializeAttachment({ ...att, presence: updatedPresence });
      const upsert = {
        type: "peer_upsert",
        userID: att.userID,
        peer: updatedPresence,
        timeMs: Date.now()
      };
      const encoded = JSON.stringify(upsert);
      for (const peerSock of this.ctx.getWebSockets()) {
        if (peerSock === ws) continue;
        try {
          peerSock.send(encoded);
        } catch {
        }
      }
      return;
    }
    if (msg.type === "signal" && msg.targetDeviceID && msg.targetDeviceID !== att.deviceID) {
      const targets = this.ctx.getWebSockets(msg.targetDeviceID);
      if (targets.length === 0) return;
      const fwd = {
        type: "signal",
        userID: att.userID,
        fromDeviceID: att.deviceID,
        kind: msg.kind,
        payload: msg.payload,
        timeMs: Date.now()
      };
      const encoded = JSON.stringify(fwd);
      for (const target of targets) {
        try {
          target.send(encoded);
        } catch {
        }
      }
      return;
    }
    if (msg.type === "ping") {
      const pong = { type: "pong", timeMs: Date.now() };
      ws.send(JSON.stringify(pong));
    }
  }
  async webSocketClose(ws) {
    this.broadcastOffline(ws);
  }
  async webSocketError(ws) {
    this.broadcastOffline(ws);
  }
  broadcastOffline(ws) {
    const att = ws.deserializeAttachment();
    try {
      ws.close();
    } catch {
    }
    if (!att) return;
    const offline = {
      type: "peer_offline",
      userID: att.userID,
      deviceID: att.deviceID,
      timeMs: Date.now()
    };
    const encoded = JSON.stringify(offline);
    for (const sock of this.ctx.getWebSockets()) {
      if (sock === ws) continue;
      const peerAtt = sock.deserializeAttachment();
      if (peerAtt?.deviceID === att.deviceID) continue;
      try {
        sock.send(encoded);
      } catch {
      }
    }
  }
  collectOnlinePeers(excludeDeviceID) {
    const out = [];
    for (const sock of this.ctx.getWebSockets()) {
      const att = sock.deserializeAttachment();
      if (!att || !att.presence?.deviceID) continue;
      if (excludeDeviceID && att.deviceID === excludeDeviceID) continue;
      out.push(att.presence);
    }
    return out;
  }
};
function compareSemVer(a, b) {
  const pa = a.replace(/^v/i, "").split(".").map((n) => parseInt(n, 10) || 0);
  const pb = b.replace(/^v/i, "").split(".").map((n) => parseInt(n, 10) || 0);
  const len = Math.max(pa.length, pb.length, 3);
  for (let i = 0; i < len; i += 1) {
    const va = pa[i] ?? 0;
    const vb = pb[i] ?? 0;
    if (va < vb) return -1;
    if (va > vb) return 1;
  }
  return 0;
}
__name(compareSemVer, "compareSemVer");
var MetaStoreDO = class extends DurableObject {
  static {
    __name(this, "MetaStoreDO");
  }
  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname === "/internal/config") {
      if (request.method === "GET") {
        const cfg = await this.ctx.storage.get("relay_config");
        return jsonResponse(cfg ?? null);
      }
      if (request.method === "PUT") {
        const cfg = await request.json();
        await this.ctx.storage.put("relay_config", cfg);
        return jsonResponse({ ok: true });
      }
      if (request.method === "DELETE") {
        await this.ctx.storage.delete("relay_config");
        return jsonResponse({ ok: true });
      }
    }
    if (url.pathname === "/v1/updates/check" && request.method === "GET") {
      const platform = (url.searchParams.get("platform") || "macos").toLowerCase();
      const arch = (url.searchParams.get("arch") || "arm64").toLowerCase();
      const channel = (url.searchParams.get("channel") || "stable").toLowerCase();
      const curVersion = url.searchParams.get("version") || "0.0.0";
      const curBuild = Number(url.searchParams.get("build") || "0") || 0;
      const releases = await this.ctx.storage.get("releases") || [];
      const match = releases.find(
        (r) => r.platform.toLowerCase() === platform && r.channel.toLowerCase() === channel && (r.arch.toLowerCase() === arch || r.arch.toLowerCase() === "universal")
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
          downloadURL: "",
          sha256: "",
          fileSizeBytes: 0,
          releaseNotes: {},
          publishedAtMs: 0
        });
      }
      const cmpLatest = compareSemVer(curVersion, match.latestVersion);
      const hasUpdate = cmpLatest < 0 || cmpLatest === 0 && curBuild < match.latestBuild;
      const cmpMin = match.minRequiredVersion ? compareSemVer(curVersion, match.minRequiredVersion) : 0;
      const belowMin = match.minRequiredVersion && cmpMin < 0 || match.minRequiredVersion && cmpMin === 0 && match.minRequiredBuild > 0 && curBuild < match.minRequiredBuild;
      const forceUpdate = Boolean(hasUpdate && (match.forceUpdate || belowMin));
      return jsonResponse({
        hasUpdate,
        forceUpdate,
        currentVersion: curVersion,
        currentBuild: curBuild,
        latestVersion: match.latestVersion,
        latestBuild: match.latestBuild,
        minRequiredVersion: match.minRequiredVersion || "",
        minRequiredBuild: match.minRequiredBuild || 0,
        downloadURL: match.downloadURL,
        sha256: match.sha256,
        ed25519Signature: match.ed25519Signature,
        fileSizeBytes: match.fileSizeBytes,
        releaseNotes: match.releaseNotes || {},
        publishedAtMs: match.publishedAtMs || 0
      });
    }
    if (url.pathname === "/v1/admin/updates" && (request.method === "POST" || request.method === "PUT")) {
      let entry;
      try {
        entry = await request.json();
      } catch {
        return apiError(400, "invalid_json", "invalid release entry json");
      }
      if (!entry.platform || !entry.latestVersion) {
        return apiError(400, "invalid_params", "platform and latestVersion are required");
      }
      entry.channel = entry.channel || "stable";
      entry.arch = entry.arch || "universal";
      entry.publishedAtMs = entry.publishedAtMs || Date.now();
      const releases = await this.ctx.storage.get("releases") || [];
      const idx = releases.findIndex(
        (r) => r.platform === entry.platform && r.arch === entry.arch && r.channel === entry.channel
      );
      if (idx >= 0) {
        releases[idx] = entry;
      } else {
        releases.push(entry);
      }
      await this.ctx.storage.put("releases", releases);
      return jsonResponse({ ok: true, release: entry });
    }
    return apiError(404, "not_found", "Not found");
  }
};

// cloudflare/src/index.ts
function withCORS(request, response) {
  const origin = request.headers.get("Origin");
  if (!origin || response.status === 101) return response;
  const headers = new Headers(response.headers);
  headers.set("Access-Control-Allow-Origin", origin);
  headers.set("Vary", "Origin");
  headers.set("Access-Control-Allow-Headers", "Authorization, Content-Type");
  headers.set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers
  });
}
__name(withCORS, "withCORS");
var index_default = {
  async fetch(request, env) {
    if (request.method === "OPTIONS") {
      return withCORS(request, new Response(null, { status: 204 }));
    }
    const res = await handleRequest(request, env);
    return withCORS(request, res);
  }
};
function compareRelaySemVer(a, b) {
  const pa = a.replace(/^v/i, "").split(".").map((n) => parseInt(n, 10) || 0);
  const pb = b.replace(/^v/i, "").split(".").map((n) => parseInt(n, 10) || 0);
  const len = Math.max(pa.length, pb.length, 3);
  for (let i = 0; i < len; i += 1) {
    const va = pa[i] ?? 0;
    const vb = pb[i] ?? 0;
    if (va < vb) return -1;
    if (va > vb) return 1;
  }
  return 0;
}
__name(compareRelaySemVer, "compareRelaySemVer");
function acceptsHTML(request) {
  return (request.headers.get("Accept") || "").toLowerCase().includes("text/html");
}
__name(acceptsHTML, "acceptsHTML");
function withQuotaHeaders(request, cfg, bodyText) {
  const headers = new Headers(request.headers);
  headers.set("X-SyncNow-Max-Envelopes", String(cfg.maxEnvelopes || 500));
  headers.set("X-SyncNow-Max-Blob-MB", String(cfg.maxBlobMB || 25));
  headers.set("X-SyncNow-Blob-TTL-Days", String(cfg.blobTTLDays || 7));
  if (bodyText !== void 0) {
    headers.set("Content-Type", "application/json");
    return new Request(request.url, {
      method: request.method,
      headers,
      body: bodyText
    });
  }
  return new Request(request, { headers });
}
__name(withQuotaHeaders, "withQuotaHeaders");
async function handleRequest(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;
  if (path === "/favicon.ico" && request.method === "GET") {
    return new Response(null, {
      status: 204,
      headers: { "Cache-Control": "public, max-age=86400" }
    });
  }
  if (path === "/setup/" && request.method === "GET") {
    return new Response(null, {
      status: 302,
      headers: {
        Location: "/setup",
        "Cache-Control": "no-store",
        "X-Robots-Tag": "noindex, nofollow"
      }
    });
  }
  if (path === "/" && request.method === "GET") {
    const cfg2 = await loadRuntimeConfig(env);
    if (!cfg2.initialized) {
      return new Response(null, {
        status: 302,
        headers: {
          Location: "/setup",
          "Cache-Control": "no-store",
          "X-Robots-Tag": "noindex, nofollow"
        }
      });
    }
    const admin = await isSetupAdmin(request, cfg2);
    if (!admin) {
      if (acceptsHTML(request)) {
        return new Response(SETUP_UI_HTML, {
          status: 401,
          headers: {
            "Content-Type": "text/html; charset=utf-8",
            "WWW-Authenticate": 'Bearer realm="syncnow-relay"',
            "Cache-Control": "no-store",
            "X-Robots-Tag": "noindex, nofollow"
          }
        });
      }
      return new Response(
        JSON.stringify({ error: "unauthorized", message: "authentication required" }),
        {
          status: 401,
          headers: {
            "Content-Type": "application/json; charset=utf-8",
            "WWW-Authenticate": 'Bearer realm="syncnow-relay"',
            "Cache-Control": "no-store",
            "X-Robots-Tag": "noindex, nofollow"
          }
        }
      );
    }
    return new Response(SETUP_UI_HTML, {
      status: 200,
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        "Cache-Control": "no-store",
        "X-Robots-Tag": "noindex, nofollow"
      }
    });
  }
  if (path === "/setup" && request.method === "GET") {
    return new Response(SETUP_UI_HTML, {
      status: 200,
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        "Cache-Control": "no-store",
        "X-Robots-Tag": "noindex, nofollow"
      }
    });
  }
  if (path === "/v1/setup/status" && request.method === "GET") {
    const cfg2 = await loadRuntimeConfig(env, true);
    if (!cfg2.initialized) {
      return jsonResponse({
        initialized: false,
        runtime: "cloudflare-workers",
        version: RELAY_VERSION,
        siteName: cfg2.siteName,
        authMode: cfg2.authMode,
        authAPI: cfg2.authAPI,
        maxEnvelopes: cfg2.maxEnvelopes,
        maxBlobMB: cfg2.maxBlobMB,
        blobTTLDays: cfg2.blobTTLDays,
        r2Enabled: Boolean(env.BLOBS),
        isAdmin: false
      });
    }
    const admin = await isSetupAdmin(request, cfg2);
    if (!admin) {
      return new Response(
        JSON.stringify({
          error: "unauthorized",
          message: "admin authentication required",
          initialized: true
        }),
        {
          status: 401,
          headers: {
            "Content-Type": "application/json; charset=utf-8",
            "WWW-Authenticate": 'Bearer realm="syncnow-relay"',
            "Cache-Control": "no-store"
          }
        }
      );
    }
    return jsonResponse({
      initialized: true,
      runtime: "cloudflare-workers",
      version: RELAY_VERSION,
      siteName: cfg2.siteName,
      authMode: cfg2.authMode,
      authAPI: cfg2.authAPI,
      ownerDisplayName: cfg2.ownerDisplayName || "",
      ownerUserID: cfg2.ownerUserID || "",
      ownerLocked: cfg2.authMode === "xtags_owner" && cfg2.allowUsers.length > 0,
      allowUsersCount: cfg2.allowUsers.length,
      allowUsers: cfg2.allowUsers,
      maxEnvelopes: cfg2.maxEnvelopes,
      maxBlobMB: cfg2.maxBlobMB,
      blobTTLDays: cfg2.blobTTLDays,
      r2Enabled: Boolean(env.BLOBS),
      isAdmin: true
    });
  }
  if (path === "/v1/setup/relay-update" && request.method === "GET") {
    const cfg2 = await loadRuntimeConfig(env, true);
    if (cfg2.initialized && !await isSetupAdmin(request, cfg2)) {
      return new Response(
        JSON.stringify({ error: "unauthorized", message: "admin authentication required" }),
        {
          status: 401,
          headers: {
            "Content-Type": "application/json; charset=utf-8",
            "WWW-Authenticate": 'Bearer realm="syncnow-relay"',
            "Cache-Control": "no-store"
          }
        }
      );
    }
    let latestVersion = RELAY_VERSION;
    let hasUpdate = false;
    let checkError;
    try {
      const up = await fetch(
        "https://raw.githubusercontent.com/zsai001/syncnow/main/package.json",
        {
          headers: {
            Accept: "application/json",
            "Cache-Control": "no-cache",
            "User-Agent": `syncnow-relay/${RELAY_VERSION}`
          }
        }
      );
      if (up.ok) {
        const parsed = await up.json().catch(() => null);
        const v = (parsed?.version || "").trim();
        if (v) {
          latestVersion = v;
          hasUpdate = compareRelaySemVer(RELAY_VERSION, v) < 0;
        } else {
          checkError = "invalid version metadata";
        }
      } else {
        checkError = `upstream returned HTTP ${up.status}`;
      }
    } catch {
      checkError = "unable to reach GitHub release metadata";
    }
    return jsonResponse(
      {
        currentVersion: RELAY_VERSION,
        latestVersion,
        hasUpdate,
        runtime: "cloudflare-workers",
        repoUrl: "https://github.com/zsai001/syncnow",
        deployUrl: "https://xtags.top/deploy/syncnow",
        ...checkError ? { checkError } : {}
      },
      200,
      { "Cache-Control": "no-store" }
    );
  }
  if (path === "/v1/setup/verify-xtags" && request.method === "POST") {
    const cfg2 = await loadRuntimeConfig(env, true);
    const body = await request.json().catch(() => null);
    if (!body) return apiError(400, "invalid_json", "invalid request body");
    if (cfg2.initialized && cfg2.authMode === "static_token") {
      return apiError(401, "unauthorized", "xtags admin login is disabled in static token mode");
    }
    const targetAuthAPI = cfg2.initialized ? cfg2.authAPI || "https://api.xtags.top" : body.authAPI || "https://api.xtags.top";
    const res = await verifyOrExchangeXTags(targetAuthAPI, body.authCode || "", body.token || "");
    if (res.errorResponse || !res.user || !res.token) {
      return res.errorResponse || apiError(400, "xtags_verify_failed", "verification failed");
    }
    if (cfg2.initialized && (!cfg2.ownerUserID || res.user.id !== cfg2.ownerUserID)) {
      return apiError(401, "unauthorized", "not authorized as relay administrator");
    }
    return jsonResponse({ token: res.token, user: res.user });
  }
  if (path === "/v1/setup/complete" && request.method === "POST") {
    const cfg2 = await loadRuntimeConfig(env, true);
    if (cfg2.initialized && !await isSetupAdmin(request, cfg2)) {
      return apiError(401, "unauthorized", "admin authentication required to modify existing setup");
    }
    const req = await request.json().catch(() => null);
    if (!req) return apiError(400, "invalid_json", "invalid json payload");
    const mode = req.authMode;
    if (mode !== "xtags_owner" && mode !== "xtags_multi" && mode !== "static_token") {
      return apiError(400, "invalid_mode", "authMode must be xtags_owner, xtags_multi, or static_token");
    }
    const next = {
      ...cfg2,
      initialized: true,
      siteName: (req.siteName || cfg2.siteName || "SyncNow Relay").trim(),
      authMode: mode,
      maxEnvelopes: req.maxEnvelopes && req.maxEnvelopes > 0 && req.maxEnvelopes <= 5e3 ? req.maxEnvelopes : cfg2.maxEnvelopes,
      maxBlobMB: req.maxBlobMB && req.maxBlobMB > 0 && req.maxBlobMB <= 512 ? req.maxBlobMB : cfg2.maxBlobMB,
      blobTTLDays: req.blobTTLDays && req.blobTTLDays > 0 && req.blobTTLDays <= 365 ? req.blobTTLDays : cfg2.blobTTLDays,
      updatedAtMs: Date.now()
    };
    if (req.adminToken && req.adminToken.trim()) {
      next.adminToken = req.adminToken.trim();
    }
    if (mode === "static_token") {
      const tok = (req.staticToken || cfg2.staticToken || "").trim();
      if (tok.length < 12) {
        return apiError(400, "weak_token", "staticToken must be at least 12 characters");
      }
      next.staticToken = tok;
      next.authAPI = "";
      next.allowUsers = [];
      next.ownerUserID = void 0;
      next.ownerDisplayName = void 0;
    } else {
      const apiBase = (req.authAPI || "https://api.xtags.top").trim().replace(/\/+$/, "");
      next.authAPI = apiBase;
      next.staticToken = void 0;
      const tok = (req.xtagsToken || extractBearerToken(request) || "").trim();
      if (tok) {
        const verified = await verifyOrExchangeXTags(apiBase, "", tok);
        if (verified.errorResponse || !verified.user) {
          return verified.errorResponse || apiError(401, "unauthorized", "xtags verification failed");
        }
        next.ownerUserID = verified.user.id;
        next.ownerDisplayName = verified.user.displayName;
      } else if (!cfg2.initialized || !next.ownerUserID) {
        return apiError(400, "owner_required", "valid xtags.top token is required to bind relay owner");
      }
      if (mode === "xtags_owner") {
        const cleaned = Array.from(
          new Set((req.allowUsers || []).map((s) => s.trim()).filter(Boolean))
        );
        next.allowUsers = cleaned.length > 0 ? cleaned : next.ownerUserID ? [next.ownerUserID] : [];
      } else {
        next.allowUsers = [];
      }
    }
    const metaStub = env.META_STORE.get(env.META_STORE.idFromName("global"));
    await metaStub.fetch("https://internal/internal/config", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(next)
    });
    invalidateConfigCache();
    return jsonResponse({ ok: true });
  }
  if (path === "/v1/setup/reset" && request.method === "POST") {
    const cfg2 = await loadRuntimeConfig(env, true);
    if (!await isSetupAdmin(request, cfg2)) {
      return apiError(401, "unauthorized", "admin authentication required");
    }
    const metaStub = env.META_STORE.get(env.META_STORE.idFromName("global"));
    await metaStub.fetch("https://internal/internal/config", { method: "DELETE" });
    invalidateConfigCache();
    return jsonResponse({ ok: true });
  }
  if (path === "/health") {
    const authRes2 = await authenticateRequest(request, env);
    const { cfg: cfg2 } = authRes2;
    let { principal: principal2 } = authRes2;
    if (!principal2) {
      const token = extractBearerToken(request);
      if (token && cfg2.adminToken && constantTimeEqual(token, cfg2.adminToken)) {
        principal2 = {
          roomID: cfg2.ownerUserID || (cfg2.authMode === "static_token" ? "static-owner" : "admin"),
          user: null,
          mode: "static_token"
        };
      } else {
        return authRes2.errorResponse || apiError(401, "unauthorized", "unauthorized");
      }
    }
    const authAPI = cfg2.authMode === "static_token" ? "" : (cfg2.authAPI || "").trim();
    const userSummary = principal2.user ? { id: principal2.user.id, displayName: principal2.user.displayName } : void 0;
    const capabilities = ["e2ee_relay", "e2ee_blobs", "same_account_signaling", "updates", "web_setup"];
    if (authAPI) capabilities.push("xtags_auth");
    if (env.BLOBS) capabilities.push("r2_blobs");
    return jsonResponse({
      status: "ok",
      service: "syncnow-relay",
      runtime: "cloudflare-workers",
      version: RELAY_VERSION,
      initialized: cfg2.initialized,
      xtagsAuth: Boolean(authAPI),
      ownerLocked: cfg2.authMode === "xtags_owner" && cfg2.allowUsers.length > 0,
      authenticated: principal2.mode !== "open",
      user: userSummary,
      capabilities
    });
  }
  if (path === "/v1/updates/check") {
    const metaStub = env.META_STORE.get(env.META_STORE.idFromName("global"));
    return metaStub.fetch(request);
  }
  if (path === "/v1/admin/updates") {
    const cfg2 = await loadRuntimeConfig(env);
    const expectedAdmin = (cfg2.adminToken || cfg2.staticToken || "").trim();
    const got = extractBearerToken(request);
    const okByToken = Boolean(expectedAdmin && got && constantTimeEqual(got, expectedAdmin));
    const okByOwner = !okByToken && await isSetupAdmin(request, cfg2);
    if (!okByToken && !okByOwner) {
      return apiError(401, "unauthorized", "invalid admin token");
    }
    const metaStub = env.META_STORE.get(env.META_STORE.idFromName("global"));
    return metaStub.fetch(request);
  }
  const authRes = await authenticateRequest(request, env);
  const { cfg } = authRes;
  let { principal } = authRes;
  if (!principal && path === "/v1/signal/peers" && request.method === "GET") {
    const token = extractBearerToken(request);
    if (token && cfg.adminToken && constantTimeEqual(token, cfg.adminToken)) {
      principal = {
        roomID: cfg.ownerUserID || (cfg.authMode === "static_token" ? "static-owner" : "admin"),
        user: null,
        mode: "static_token"
      };
    }
  }
  if (!principal) {
    return authRes.errorResponse || apiError(401, "unauthorized", "unauthorized");
  }
  if (path === "/v1/signal/ws" || path === "/v1/signal/peers") {
    const roomStub = env.SIGNALING_ROOM.get(env.SIGNALING_ROOM.idFromName(principal.roomID));
    const fwdHeaders = new Headers(request.headers);
    fwdHeaders.set("X-SyncNow-Room-ID", principal.roomID);
    const fwdReq = new Request(request, { headers: fwdHeaders });
    return roomStub.fetch(fwdReq);
  }
  if (path === "/ws" || path === "/v1/sync" || path.startsWith("/v1/blobs/")) {
    const groupHash = (url.searchParams.get("group") || "").trim();
    if (!SAFE_ID_REGEX.test(groupHash)) {
      return apiError(400, "invalid_group", "valid group query parameter is required");
    }
    const groupStub = env.RELAY_GROUP.get(env.RELAY_GROUP.idFromName(groupHash));
    return groupStub.fetch(withQuotaHeaders(request, cfg));
  }
  if (path === "/v1/push" && request.method === "POST") {
    const bodyText = await request.text();
    let parsed;
    try {
      parsed = JSON.parse(bodyText);
    } catch {
      return apiError(400, "invalid_json", "invalid json");
    }
    const groupHash = (parsed.groupHash || "").trim();
    if (!SAFE_ID_REGEX.test(groupHash)) {
      return apiError(400, "invalid_group", "invalid groupHash");
    }
    const groupStub = env.RELAY_GROUP.get(env.RELAY_GROUP.idFromName(groupHash));
    return groupStub.fetch(withQuotaHeaders(request, cfg, bodyText));
  }
  return apiError(404, "not_found", "Not found");
}
__name(handleRequest, "handleRequest");
export {
  MetaStoreDO,
  RelayGroupDO,
  SignalingRoomDO,
  index_default as default
};
