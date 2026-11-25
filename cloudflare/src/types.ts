export interface Env {
  RELAY_GROUP: DurableObjectNamespace;
  SIGNALING_ROOM: DurableObjectNamespace;
  META_STORE: DurableObjectNamespace;
  BLOBS?: R2Bucket;

  SYNCNOW_AUTH_API?: string;
  SYNCNOW_ALLOW_USERS?: string;
  SYNCNOW_RELAY_TOKEN?: string;
  SYNCNOW_ADMIN_TOKEN?: string;
  SYNCNOW_MAX_ENVELOPES?: string;
  SYNCNOW_MAX_BLOB_MB?: string;
  SYNCNOW_BLOB_TTL_DAYS?: string;
}

export interface XTagsUser {
  id: string;
  email?: string | null;
  displayName: string;
  avatarUrl?: string | null;
  role?: string;
  providers?: string[];
}

export interface AuthPrincipal {
  roomID: string;
  user: XTagsUser | null;
  mode: 'xtags' | 'static_token' | 'open';
}

export interface Envelope {
  id: string;
  seq: number;
  groupHash: string;
  senderDeviceID: string;
  createdAtMs: number;
  ciphertextBase64: string;
  blobID?: string;
  blobSize?: number;
}

export interface SignalEndpoint {
  host: string;
  tcpPort: number;
  udpPort: number;
}

export interface SignalPeerPresence {
  deviceID: string;
  deviceName: string;
  platform: string;
  signingPublicKeyBase64: string;
  accountCert?: unknown;
  lanEndpoints: SignalEndpoint[];
  observedPublicIP?: string;
  tcpPort: number;
  udpPort: number;
  appVersion: string;
  online: boolean;
  updatedAtMs: number;
}

export interface SignalClientMessage {
  type: 'register' | 'signal' | 'ping';
  presence?: SignalPeerPresence;
  targetDeviceID?: string;
  kind?: string;
  payload?: string;
}

export interface SignalServerMessage {
  type: 'peers_snapshot' | 'peer_upsert' | 'peer_offline' | 'signal' | 'pong';
  userID?: string;
  peers?: SignalPeerPresence[];
  peer?: SignalPeerPresence;
  deviceID?: string;
  fromDeviceID?: string;
  kind?: string;
  payload?: string;
  timeMs?: number;
}

export interface ReleaseEntry {
  platform: string;
  arch: string;
  channel: string;
  latestVersion: string;
  latestBuild: number;
  minRequiredVersion: string;
  minRequiredBuild: number;
  forceUpdate: boolean;
  downloadURL: string;
  sha256: string;
  ed25519Signature?: string;
  fileSizeBytes: number;
  releaseNotes: Record<string, string>;
  publishedAtMs: number;
}

export interface DynamicRelayConfig {
  initialized: boolean;
  siteName: string;
  authMode: 'xtags_owner' | 'xtags_multi' | 'static_token';
  authAPI: string;
  ownerUserID?: string;
  ownerDisplayName?: string;
  allowUsers: string[];
  staticToken?: string;
  adminToken?: string;
  maxEnvelopes: number;
  maxBlobMB: number;
  blobTTLDays: number;
  updatedAtMs: number;
}

export const SAFE_ID_REGEX = /^[a-zA-Z0-9._-]{1,128}$/;
export const RELAY_VERSION = '0.3.2';

export function jsonResponse(payload: unknown, status = 200, extraHeaders?: HeadersInit): Response {
  const headers = new Headers(extraHeaders);
  headers.set('Content-Type', 'application/json');
  return new Response(JSON.stringify(payload), { status, headers });
}

export function apiError(status: number, code: string, message: string): Response {
  return jsonResponse({ error: code, message }, status);
}
