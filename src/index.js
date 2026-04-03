import 'dotenv/config';
import { mkdirSync, readFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import argon2 from 'argon2';
import speakeasy from 'speakeasy';
import QRCode from 'qrcode';
import { Provider, errors } from 'oidc-provider';
import { generateAuthenticationOptions, generateRegistrationOptions, verifyAuthenticationResponse, verifyRegistrationResponse } from '@simplewebauthn/server';
import { clearUserPasskeys, createClient, createUser, deleteClient, deleteUser, ensureClientPostLogoutRedirectUri, ensureClientRedirectUri, ensureSchema, findPasskeyByCredentialId, findUserById, findUserByUsername, getClients, listUsers, seedAdminFromEnv, seedClientFromEnv, touchUserPasskeyCounter, updateClient, updateClientRedirectUris, updateUser, updateUserProfile, upsertGoogleUser, upsertUserPasskey } from './db.js';
import { findAccount } from './account.js';
import { renderConsent, renderExpiredSession, renderLogin, renderLogout, renderLogoutAutoSubmit, renderLogoutSuccess, renderOidcSessionsAdmin, renderPasskeyOnboarding, renderProviderError, renderRedirectConfigAdmin, renderRegister, renderTotpQrSetup, renderUsersAdmin } from './html.js';
import { cleanupExpiredOidcRecords, ensureOidcStore, JsonAdapter, listOidcStoreOverview, removeOidcRecord, revokeClientCredentialsToken, revokeOidcByGrantId, revokeOidcBySessionUid } from './oidc-adapter.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const publicDir = join(__dirname, '..', 'public');
const app = express();
const port = Number(process.env.PORT || 9000);
const issuer = process.env.ISSUER || `http://localhost:${port}`;
const issuerUrl = new URL(issuer);
const cookieKeys = (process.env.COOKIE_KEYS || '').split(',').map((s) => s.trim()).filter(Boolean);
const trustProxy = String(process.env.TRUST_PROXY || 'true').toLowerCase() !== 'false';
const allowedOrigins = (process.env.ALLOWED_ORIGINS || 'http://localhost:9000,http://localhost:8080,http://localhost')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);
const allowedOriginSet = new Set([issuerUrl.origin, ...allowedOrigins.map(normalizeOrigin).filter(Boolean)]);
const runtimeConfig = {
  twoFactorEnabled: String(process.env.TWO_FACTOR_ENABLED || 'true').toLowerCase() !== 'false',
  consentEnabled: String(process.env.CONSENT_ENABLED || 'true').toLowerCase() !== 'false',
  googleOAuthEnabled: String(process.env.GOOGLE_OAUTH_ENABLED || 'true').toLowerCase() !== 'false',
  passkeyEnabled: String(process.env.PASSKEY_ENABLED || 'false').toLowerCase() === 'true',
  confirmLogout: String(process.env.CONFIRM_LOGOUT || 'true').toLowerCase() !== 'false',
};
const indexTemplate = readFileSync(join(publicDir, 'index.html'), 'utf8');
const authWidgetTemplate = readFileSync(join(publicDir, 'authWidget.html'), 'utf8');
const flowDiagramTemplate = readFileSync(join(publicDir, 'flowDiagram.html'), 'utf8');

function normalizeBasePath(value) {
  const raw = String(value || '').trim();
  if (!raw || raw === '/') return '';
  return `/${raw.replace(/^\/+|\/+$/g, '')}`;
}

function resolvePath(base, path = '/') {
  const normalizedBase = normalizeBasePath(base);
  const normalizedPath = String(path || '/').startsWith('/') ? String(path || '/') : `/${String(path || '/')}`;
  return normalizedBase ? `${normalizedBase}${normalizedPath}` : normalizedPath;
}

function stripBasePath(path, base) {
  const normalizedPath = String(path || '/').startsWith('/') ? String(path || '/') : `/${String(path || '/')}`;
  const normalizedBase = normalizeBasePath(base);
  if (!normalizedBase) return normalizedPath;
  if (normalizedPath === normalizedBase) return '/';
  if (normalizedPath.startsWith(`${normalizedBase}/`)) {
    return normalizedPath.slice(normalizedBase.length);
  }
  return normalizedPath;
}

const basePath = normalizeBasePath(process.env.BASE_PATH || issuerUrl.pathname);
const baseHref = basePath ? `${basePath}/` : '/';

function normalizeOrigin(value) {
  try {
    return new URL(value).origin;
  } catch {
    return '';
  }
}

function isCorsOriginAllowed(rawOrigin) {
  const origin = normalizeOrigin(rawOrigin);
  if (!origin) return false;
  if (allowedOriginSet.has(origin)) return true;

  const clients = getClients();
  for (const client of clients) {
    const redirectUris = [
      ...(client?.redirectUris || []),
      ...(client?.redirect_uris || []),
      ...(client?.postLogoutRedirectUris || []),
      ...(client?.post_logout_redirect_uris || []),
    ];
    for (const uri of redirectUris) {
      if (normalizeOrigin(uri) === origin) {
        return true;
      }
    }
  }

  return false;
}

function inferRequestProtocol(req) {
  const forwardedProto = String(req.get('x-forwarded-proto') || '').split(',')[0].trim().toLowerCase();
  if (forwardedProto === 'http' || forwardedProto === 'https') return forwardedProto;

  const forwardedHeader = String(req.get('forwarded') || '');
  const protoMatch = forwardedHeader.match(/(?:^|[;,]\s*)proto=(https?|\"https?\"|\'https?\')/i);
  if (protoMatch?.[1]) {
    return String(protoMatch[1]).replace(/['"]/g, '').toLowerCase();
  }

  const origin = normalizeOrigin(req.get('origin') || '');
  const referer = normalizeOrigin(req.get('referer') || '');
  const forwardedHost = String(req.get('x-forwarded-host') || '').split(',')[0].trim().toLowerCase();
  const host = String(forwardedHost || req.get('host') || '').trim().toLowerCase();
  const originUrl = origin ? new URL(origin) : null;
  const refererUrl = referer ? new URL(referer) : null;

  if (originUrl && originUrl.host.toLowerCase() === host && originUrl.protocol === 'https:') return 'https';
  if (refererUrl && refererUrl.host.toLowerCase() === host && refererUrl.protocol === 'https:') return 'https';

  const hostPort = host.includes(':') ? Number(host.split(':').pop()) : null;
  if (hostPort === 443 || hostPort === 55443) return 'https';

  if (req.socket?.encrypted) return 'https';
  const reqProtocol = String(req.protocol || '').toLowerCase();
  if (reqProtocol === 'http' || reqProtocol === 'https') return reqProtocol;
  return issuerUrl.protocol.replace(':', '') || 'http';
}

function getRequestOrigin(req) {
  const protocol = inferRequestProtocol(req);
  const host = String(req.get('x-forwarded-host') || req.get('host') || '').split(',')[0].trim();
  return normalizeOrigin(`${protocol}://${host}`);
}

function escapeRegExp(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function normalizeAbsoluteUrlsForHosts(html, protocol, hosts = []) {
  const markup = String(html || '');
  const normalizedProtocol = protocol === 'https' ? 'https' : 'http';
  if (!markup) return markup;
  let output = markup;
  for (const rawHost of hosts) {
    const host = String(rawHost || '').trim();
    if (!host) continue;
    const pattern = new RegExp(`https?:\\/\\/${escapeRegExp(host)}`, 'gi');
    output = output.replace(pattern, `${normalizedProtocol}://${host}`);
  }
  return output;
}

function hostFromUrl(value) {
  try {
    return new URL(value).host;
  } catch {
    return '';
  }
}

function getGoogleCallbackUrl(req) {
  const requestOrigin = req ? getRequestOrigin(req) : '';
  if (requestOrigin) {
    const requestBasePath = normalizeBasePath(req.baseUrl || basePath);
    return new URL(resolvePath(requestBasePath, googleCallbackRoutePath), `${requestOrigin}/`).toString();
  }
  if (configuredGoogleCallbackUrl) return configuredGoogleCallbackUrl;
  return new URL(googleCallbackPath, `${issuerUrl.origin}/`).toString();
}

function getPasskeyRpId(req) {
  if (configuredPasskeyRpId) return configuredPasskeyRpId;
  const host = String(req?.get('x-forwarded-host') || req?.get('host') || '')
    .split(',')[0]
    .trim()
    .toLowerCase();
  const hostname = host.includes(':') ? host.split(':')[0] : host;
  return hostname || issuerUrl.hostname;
}

function getPasskeyOrigin(req) {
  if (configuredPasskeyOrigin) return configuredPasskeyOrigin;
  return getRequestOrigin(req) || issuerUrl.origin;
}

function parseBearerToken(req) {
  const auth = String(req.get('authorization') || '');
  const match = auth.match(/^Bearer\s+(.+)$/i);
  return match ? String(match[1] || '').trim() : '';
}

async function resolveAccessToken(req) {
  const tokenValue = parseBearerToken(req);
  if (!tokenValue) return null;
  const token = await provider.AccessToken.find(tokenValue);
  if (!token) return null;
  if (typeof token.isExpired === 'function' && token.isExpired()) return null;
  return token;
}

if (cookieKeys.length < 3) {
  throw new Error('COOKIE_KEYS must include at least 3 comma-separated secrets');
}

mkdirSync('data/oauth', { recursive: true });
ensureSchema();
ensureOidcStore();
await seedAdminFromEnv();
seedClientFromEnv();

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  validate: {
    trustProxy: false,
    xForwardedForHeader: false,
  },
});

const totpChallenges = new Map();
const totpSetupSessions = new Map();
const googleLoginStates = new Map();
const googleCallbackSessions = new Map();
const interactionCallbackSessions = new Map();
const passkeyAuthSessions = new Map();
const passkeyRegistrationSessions = new Map();
const passkeyCompletionSessions = new Map();
const passkeyOnboardingSessions = new Map();

const googleClientId = process.env.GOOGLE_CLIENT_ID || '';
const googleClientSecret = process.env.GOOGLE_CLIENT_SECRET || '';
const defaultGoogleCallbackPath = resolvePath(basePath, '/auth/google/callback');
const googleCallbackPath = process.env.GOOGLE_CALLBACK_PATH || defaultGoogleCallbackPath;
const googleCallbackRoutePath = stripBasePath(googleCallbackPath, basePath);
const configuredGoogleCallbackUrl = process.env.GOOGLE_CALLBACK_URL || '';
const googleConfigured = Boolean(googleClientId && googleClientSecret);
const configuredPasskeyRpId = process.env.PASSKEY_RP_ID || '';
const configuredPasskeyOrigin = process.env.PASSKEY_ORIGIN || '';
const passkeyRpName = process.env.PASSKEY_RP_NAME || 'Local OAuth2 Server';

function renderTemplate(template) {
  const appConfig = JSON.stringify({ basePath, baseHref, issuer }).replace(/</g, '\\u003c');
  return template.replace(
    '<head>',
    `<head>\n  <base href="${baseHref}" />\n  <script>window.__APP_CONFIG__ = ${appConfig};</script>`,
  );
}

function getQrSetupUrl() {
  const setupToken = process.env.SETUP_TOKEN || '';
  const adminUser = process.env.ADMIN_USERNAME || 'admin';
  if (!setupToken) return '';
  return resolvePath(basePath, `/setup/2fa-qr/${encodeURIComponent(adminUser)}?token=${encodeURIComponent(setupToken)}`);
}

function getSetupToken(req) {
  const setupToken = process.env.SETUP_TOKEN || '';
  const queryToken = String(req.query.token || '');
  const headerToken = req.get('x-setup-token') || '';
  if (!setupToken || (headerToken !== setupToken && queryToken !== setupToken)) {
    return '';
  }
  return setupToken;
}

function requireSetupToken(req, res) {
  const token = getSetupToken(req);
  if (!token) {
    res.status(403).json({ error: 'Forbidden' });
    return '';
  }
  return token;
}

function isTwoFactorEnabled() {
  return runtimeConfig.twoFactorEnabled;
}

function isConsentEnabled() {
  return runtimeConfig.consentEnabled;
}

function isGoogleOAuthEnabled() {
  return googleConfigured && runtimeConfig.googleOAuthEnabled;
}

function isConfirmLogoutEnabled() {
  return runtimeConfig.confirmLogout;
}

function isPasskeyEnabled() {
  return runtimeConfig.passkeyEnabled;
}

function parseBooleanFlag(value, fallback = false) {
  const normalized = String(value ?? '').trim().toLowerCase();
  if (!normalized) return fallback;
  if (['true', '1', 'yes', 'on'].includes(normalized)) return true;
  if (['false', '0', 'no', 'off'].includes(normalized)) return false;
  return fallback;
}

function toBase64Url(value) {
  if (typeof value === 'string') return value;
  if (value == null) return '';
  return Buffer.from(value).toString('base64url');
}

function fromBase64Url(value) {
  return Buffer.from(String(value || ''), 'base64url');
}

function buildAbsoluteAppUrl(path) {
  return new URL(resolvePath(basePath, path), `${issuerUrl.origin}/`).toString();
}

function getSafeCallbackUrl(rawValue) {
  const raw = String(rawValue || '').trim();
  if (!raw) return '';

  try {
    const url = raw.startsWith('/')
      ? new URL(raw, `${issuerUrl.origin}/`)
      : new URL(raw);
    const origin = normalizeOrigin(url.toString());
    if (!origin) return '';
    if (!allowedOrigins.map(normalizeOrigin).includes(origin)) return '';
    return url.toString();
  } catch {
    return '';
  }
}

function getInteractionCallbackUrl(params) {
  return getSafeCallbackUrl(params?.callbackUrl || params?.callback_url);
}

function getInteractionBackUrl(params) {
  return getSafeCallbackUrl(params?.backUrl || params?.back_url || params?.backurl);
}

async function buildQrSetupPayload(user) {
  if (!user?.totp_secret || !user?.username) {
    return null;
  }

  const otpauthUrl = speakeasy.otpauthURL({
    secret: user.totp_secret,
    label: `OAuth2 (${user.username})`,
    issuer: 'Local OAuth2 Server',
    encoding: 'base32',
  });

  return {
    username: user.username,
    otpauthUrl,
    dataUrl: await QRCode.toDataURL(otpauthUrl),
  };
}

async function getQrSetupPayload(username) {
  const user = findUserByUsername(username);
  return buildQrSetupPayload(user);
}

function createTotpChallenge(uid, accountId, intent = 'login') {
  const challenge = randomUUID();
  totpChallenges.set(challenge, {
    uid,
    accountId,
    intent,
    expiresAt: Date.now() + 3 * 60 * 1000,
  });
  return challenge;
}

function createTotpSetupSession(uid, accountId) {
  const token = randomUUID();
  totpSetupSessions.set(token, {
    uid,
    accountId,
    expiresAt: Date.now() + 10 * 60 * 1000,
  });
  return token;
}

function getInteractionQrSetupUrl(uid, accountId) {
  const token = createTotpSetupSession(uid, accountId);
  return resolvePath(basePath, `/interaction/${encodeURIComponent(uid)}/2fa-qr?token=${encodeURIComponent(token)}`);
}

function getTotpSetupSession(token, uid) {
  const data = totpSetupSessions.get(token);
  if (!data) return null;
  if (data.uid !== uid) return null;
  if (Date.now() > data.expiresAt) {
    totpSetupSessions.delete(token);
    return null;
  }
  return data;
}

function getGoogleLoginUrl(uid) {
  if (!isGoogleOAuthEnabled()) return '';
  return getGoogleRegisterUrl(uid);
}

function getGoogleRegisterUrl(uid) {
  if (!isGoogleOAuthEnabled()) return '';
  return resolvePath(basePath, `/interaction/${encodeURIComponent(uid)}/register/google`);
}

function createGoogleState(uid, mode = 'login') {
  const state = randomUUID();
  googleLoginStates.set(state, {
    uid,
    mode,
    expiresAt: Date.now() + 10 * 60 * 1000,
  });
  return state;
}

function consumeGoogleState(state) {
  const data = googleLoginStates.get(state);
  googleLoginStates.delete(state);
  if (!data) return null;
  if (Date.now() > data.expiresAt) return null;
  return data;
}

function createGoogleCallbackSession(uid, accountId, mode = 'login') {
  const token = randomUUID();
  googleCallbackSessions.set(token, {
    uid,
    accountId,
    mode,
    expiresAt: Date.now() + 3 * 60 * 1000,
  });
  return token;
}

function createInteractionCallbackSession(uid, result, mergeWithLastSubmission) {
  const token = randomUUID();
  interactionCallbackSessions.set(token, {
    uid,
    result,
    mergeWithLastSubmission,
    expiresAt: Date.now() + 5 * 60 * 1000,
  });
  return token;
}

function consumeInteractionCallbackSession(token, uid) {
  const data = interactionCallbackSessions.get(token);
  interactionCallbackSessions.delete(token);
  if (!data) return null;
  if (data.uid !== uid) return null;
  if (Date.now() > data.expiresAt) return null;
  return data;
}

function consumeGoogleCallbackSession(token, uid) {
  const data = googleCallbackSessions.get(token);
  googleCallbackSessions.delete(token);
  if (!data) return null;
  if (data.uid !== uid) return null;
  if (Date.now() > data.expiresAt) return null;
  return data;
}

function createPasskeyAuthSession(uid, challenge) {
  const token = randomUUID();
  passkeyAuthSessions.set(token, {
    uid,
    challenge,
    expiresAt: Date.now() + 3 * 60 * 1000,
  });
  return token;
}

function consumePasskeyAuthSession(token, uid) {
  const data = passkeyAuthSessions.get(token);
  passkeyAuthSessions.delete(token);
  if (!data) return null;
  if (data.uid !== uid) return null;
  if (Date.now() > data.expiresAt) return null;
  return data;
}

function createPasskeyRegistrationSession(username, challenge) {
  const token = randomUUID();
  passkeyRegistrationSessions.set(token, {
    username,
    challenge,
    expiresAt: Date.now() + 5 * 60 * 1000,
  });
  return token;
}

function consumePasskeyRegistrationSession(token, username) {
  const data = passkeyRegistrationSessions.get(token);
  passkeyRegistrationSessions.delete(token);
  if (!data) return null;
  if (data.username !== username) return null;
  if (Date.now() > data.expiresAt) return null;
  return data;
}

function createPasskeyCompletionSession(uid, payload) {
  const token = randomUUID();
  passkeyCompletionSessions.set(token, {
    uid,
    ...payload,
    expiresAt: Date.now() + 3 * 60 * 1000,
  });
  return token;
}

function consumePasskeyCompletionSession(token, uid) {
  const data = passkeyCompletionSessions.get(token);
  passkeyCompletionSessions.delete(token);
  if (!data) return null;
  if (data.uid !== uid) return null;
  if (Date.now() > data.expiresAt) return null;
  return data;
}

function createPasskeyOnboardingSession(uid, accountId) {
  const token = randomUUID();
  passkeyOnboardingSessions.set(token, {
    uid,
    accountId,
    challenge: '',
    expiresAt: Date.now() + 10 * 60 * 1000,
  });
  return token;
}

function getPasskeyOnboardingSession(token, uid) {
  const data = passkeyOnboardingSessions.get(token);
  if (!data) return null;
  if (data.uid !== uid) return null;
  if (Date.now() > data.expiresAt) {
    passkeyOnboardingSessions.delete(token);
    return null;
  }
  return data;
}

function consumePasskeyOnboardingSession(token, uid) {
  const data = getPasskeyOnboardingSession(token, uid);
  if (!data) return null;
  passkeyOnboardingSessions.delete(token);
  return data;
}

async function exchangeGoogleCode(code, redirectUri) {
  const response = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({
      code,
      client_id: googleClientId,
      client_secret: googleClientSecret,
      redirect_uri: redirectUri,
      grant_type: 'authorization_code',
    }),
  });

  if (!response.ok) {
    const body = await response.text();
    throw new Error(`Google token exchange failed with status ${response.status}: ${body}`);
  }

  return response.json();
}

async function fetchGoogleProfile(accessToken) {
  const response = await fetch('https://openidconnect.googleapis.com/v1/userinfo', {
    headers: {
      authorization: `Bearer ${accessToken}`,
    },
  });

  if (!response.ok) {
    const body = await response.text();
    throw new Error(`Google userinfo failed with status ${response.status}: ${body}`);
  }

  return response.json();
}

async function startGoogleAuth(req, res, next) {
  try {
    if (!isGoogleOAuthEnabled()) {
      res.status(404).send('Google login is not configured');
      return;
    }

    const { uid } = req.params;
    const mode = 'register';
    await provider.interactionDetails(req, res);

    const state = createGoogleState(uid, mode);
    const redirectUri = getGoogleCallbackUrl(req);
    const redirectUrl = new URL('https://accounts.google.com/o/oauth2/v2/auth');
    redirectUrl.searchParams.set('client_id', googleClientId);
    redirectUrl.searchParams.set('redirect_uri', redirectUri);
    redirectUrl.searchParams.set('response_type', 'code');
    redirectUrl.searchParams.set('scope', 'openid profile email');
    redirectUrl.searchParams.set('state', state);
    redirectUrl.searchParams.set('access_type', 'online');
    redirectUrl.searchParams.set('prompt', 'select_account');

    res.redirect(redirectUrl.toString());
  } catch (err) {
    if (isMissingInteractionSession(err)) {
      respondExpiredSession(res);
      return;
    }
    next(err);
  }
}

function consumeTotpChallenge(challenge, uid) {
  const data = totpChallenges.get(challenge);
  totpChallenges.delete(challenge);
  if (!data) return null;
  if (data.uid !== uid) return null;
  if (Date.now() > data.expiresAt) return null;
  return data;
}

function verifyTotpToken(user, otp) {
  if (!user?.totp_secret) return false;

  return speakeasy.totp.verify({
    secret: user.totp_secret,
    encoding: 'base32',
    token: String(otp).replace(/\s+/g, ''),
    window: 1,
  });
}

function isTotpRequired(user) {
  return isTwoFactorEnabled() && Boolean(user?.totp_enabled);
}

function hasPasskeys(user) {
  return Array.isArray(user?.passkeys) && user.passkeys.length > 0;
}

async function finishLogin(req, res, accountId) {
  const result = {
    login: {
      accountId,
      remember: false,
    },
  };
  await finishInteraction(req, res, result, {
    mergeWithLastSubmission: false,
    callbackStage: 'session_ready',
    callbackStatus: 'success',
  });
}

async function finishInteraction(req, res, result, {
  mergeWithLastSubmission = false,
  callbackStage = '',
  callbackStatus = '',
} = {}) {
  const details = await provider.interactionDetails(req, res);
  const callbackUrl = getInteractionCallbackUrl(details?.params);

  if (callbackUrl) {
    const token = createInteractionCallbackSession(details.uid, result, mergeWithLastSubmission);
    const continueUrl = buildAbsoluteAppUrl(`/interaction/${encodeURIComponent(details.uid)}/continue?token=${encodeURIComponent(token)}`);
    const redirectUrl = new URL(callbackUrl);
    if (callbackStage) redirectUrl.searchParams.set('stage', callbackStage);
    if (callbackStatus) redirectUrl.searchParams.set('status', callbackStatus);
    redirectUrl.searchParams.set('uid', details.uid);
    redirectUrl.searchParams.set('continueUrl', continueUrl);
    res.redirect(redirectUrl.toString());
    return;
  }

  await provider.interactionFinished(req, res, result, { mergeWithLastSubmission });
}

function isMissingInteractionSession(error) {
  return error?.error === 'invalid_request' && error?.error_description === 'interaction session not found';
}

function respondExpiredSession(res) {
  res.status(401).setHeader('Content-Type', 'text/html; charset=utf-8');
  res.end(renderExpiredSession({ basePath }));
}

function renderLoginPage(params = {}) {
  return renderLogin({
    ...params,
    passkeyEnabled: isPasskeyEnabled(),
    registerUrl: params.registerUrl || (params.uid ? resolvePath(basePath, `/interaction/${encodeURIComponent(params.uid)}/register`) : ''),
  });
}

function renderRegisterPage(params = {}) {
  return renderRegister({
    ...params,
    passkeyEnabled: isPasskeyEnabled(),
    loginUrl: params.loginUrl || (params.uid ? resolvePath(basePath, `/interaction/${encodeURIComponent(params.uid)}`) : ''),
  });
}

async function renderPasskeyOnboardingForUser(req, res, uid, user) {
  const details = await provider.interactionDetails(req, res);
  const backUrl = getInteractionBackUrl(details?.params);
  const token = createPasskeyOnboardingSession(uid, user.id);
  res.status(200).setHeader('Content-Type', 'text/html; charset=utf-8');
  res.end(renderPasskeyOnboarding({
    basePath,
    uid,
    token,
    username: user.username,
    backUrl,
  }));
}

setInterval(() => {
  const now = Date.now();
  for (const [key, value] of totpChallenges.entries()) {
    if (value.expiresAt < now) totpChallenges.delete(key);
  }
  for (const [key, value] of totpSetupSessions.entries()) {
    if (value.expiresAt < now) totpSetupSessions.delete(key);
  }
  for (const [key, value] of googleLoginStates.entries()) {
    if (value.expiresAt < now) googleLoginStates.delete(key);
  }
  for (const [key, value] of googleCallbackSessions.entries()) {
    if (value.expiresAt < now) googleCallbackSessions.delete(key);
  }
  for (const [key, value] of interactionCallbackSessions.entries()) {
    if (value.expiresAt < now) interactionCallbackSessions.delete(key);
  }
  for (const [key, value] of passkeyAuthSessions.entries()) {
    if (value.expiresAt < now) passkeyAuthSessions.delete(key);
  }
  for (const [key, value] of passkeyRegistrationSessions.entries()) {
    if (value.expiresAt < now) passkeyRegistrationSessions.delete(key);
  }
  for (const [key, value] of passkeyCompletionSessions.entries()) {
    if (value.expiresAt < now) passkeyCompletionSessions.delete(key);
  }
  for (const [key, value] of passkeyOnboardingSessions.entries()) {
    if (value.expiresAt < now) passkeyOnboardingSessions.delete(key);
  }
}, 30_000).unref();

setInterval(() => {
  const removed = cleanupExpiredOidcRecords();
  if (removed > 0) {
    console.log(`[oidc-store] removed expired records: ${removed}`);
  }
}, 60_000).unref();

const provider = new Provider(issuer, {
  clients: [],
  pkce: {
    methods: ['S256'],
    required: () => true,
  },
  scopes: ['openid', 'profile', 'email', 'offline_access'],
  claims: {
    openid: ['sub'],
    profile: ['preferred_username', 'picture'],
    email: ['email'],
  },
  features: {
    devInteractions: { enabled: false },
    clientCredentials: { enabled: true },
    introspection: { enabled: true },
    revocation: { enabled: true },
    rpInitiatedLogout: {
      enabled: true,
      logoutSource(ctx, form) {
        const forwardedHost = String(ctx.get('x-forwarded-host') || '').split(',')[0].trim();
        const host = String(forwardedHost || ctx.host || '').split(',')[0].trim();
        const protocol = inferRequestProtocol({
          get: (name) => ctx.get(name),
          socket: ctx.req?.socket,
        });
        const normalizedForm = normalizeAbsoluteUrlsForHosts(form, protocol, [
          host,
          forwardedHost,
          ctx.host,
          issuerUrl.host,
          ...allowedOrigins.map(hostFromUrl),
        ]);
        ctx.type = 'html';
        ctx.body = isConfirmLogoutEnabled()
          ? renderLogout({ basePath, host: host || ctx.host, form: normalizedForm })
          : renderLogoutAutoSubmit({ basePath, form: normalizedForm });
      },
      postLogoutSuccessSource(ctx) {
        ctx.type = 'html';
        ctx.body = renderLogoutSuccess({
          basePath,
          clientName: ctx.oidc.client?.clientName || ctx.oidc.client?.clientId || '',
        });
      },
    },
  },
  findAccount,
  ttl: {
    AccessToken: 60 * 60,
    IdToken: 10 * 60,
    RefreshToken: 14 * 24 * 60 * 60,
    Session: 24 * 60 * 60,
    Interaction: 15 * 60,
  },
  cookies: {
    keys: cookieKeys,
    long: {
      secure: issuer.startsWith('https://'),
      sameSite: 'lax',
      httpOnly: true,
    },
    short: {
      secure: issuer.startsWith('https://'),
      sameSite: 'lax',
      httpOnly: true,
    },
  },
  interactions: {
    url(_ctx, interaction) {
      return resolvePath(basePath, `/interaction/${interaction.uid}`);
    },
  },
  renderError(ctx, out, defaultError) {
    const payload = {
      basePath,
      error: out?.error || defaultError?.error || 'server_error',
      error_description: out?.error_description || defaultError?.error_description || defaultError?.message || 'oops! something went wrong',
      state: out?.state || '',
      iss: out?.iss || issuer,
    };
    ctx.type = 'html';
    ctx.status = Number(out?.statusCode || defaultError?.status || 500);
    ctx.body = renderProviderError(payload);
  },
  extraParams: {
    callbackUrl(_ctx, value) {
      if (value === undefined) return;
      if (!getSafeCallbackUrl(value)) {
        throw new errors.InvalidRequest('"callbackUrl" is invalid or not allowed');
      }
    },
    backUrl(_ctx, value) {
      if (value === undefined) return;
      if (!getSafeCallbackUrl(value)) {
        throw new errors.InvalidRequest('"backUrl" is invalid or not allowed');
      }
    },
  },
  clientBasedCORS(_ctx, origin, client) {
    const normalizedOrigin = normalizeOrigin(origin);
    if (!normalizedOrigin) return false;

    if (allowedOrigins.map(normalizeOrigin).includes(normalizedOrigin)) {
      return true;
    }

    const redirectUris = [
      ...(client?.redirectUris || []),
      ...(client?.redirect_uris || []),
      ...(client?.postLogoutRedirectUris || []),
      ...(client?.post_logout_redirect_uris || []),
    ];

    return redirectUris
      .map((uri) => normalizeOrigin(uri))
      .includes(normalizedOrigin);
  },
  formats: {
    AccessToken: 'jwt',
  },
  adapter: JsonAdapter,
});

provider.proxy = trustProxy;

app.set('trust proxy', trustProxy);
app.use((req, res, next) => {
  const externalProtocol = inferRequestProtocol(req);
  const forwardedHost = String(req.get('x-forwarded-host') || '').split(',')[0].trim();
  const host = String(forwardedHost || req.get('host') || '').split(',')[0].trim();
  const reqHost = String(req.get('host') || '').split(',')[0].trim();
  const knownHosts = new Set([host, forwardedHost, reqHost].filter(Boolean).map((value) => value.toLowerCase()));

  if (externalProtocol) {
    req.headers['x-forwarded-proto'] = externalProtocol;
  }
  if (host) {
    req.headers['x-forwarded-host'] = host;
  }

  const originalSetHeader = res.setHeader.bind(res);
  res.setHeader = (name, value) => {
    if (String(name).toLowerCase() === 'location' && typeof value === 'string' && host) {
      try {
        const locationUrl = new URL(value);
        const locationHost = String(locationUrl.host || '').toLowerCase();
        if (knownHosts.has(locationHost)) {
          const relativeLocation = `${locationUrl.pathname}${locationUrl.search}${locationUrl.hash}`;
          return originalSetHeader(name, relativeLocation || '/');
        }
      } catch {
        const expectedHttpPrefix = `http://${host}/`;
        const expectedHttpsPrefix = `https://${host}/`;
        if (value.startsWith(expectedHttpPrefix) && externalProtocol === 'https') {
          return originalSetHeader(name, value.replace(expectedHttpPrefix, expectedHttpsPrefix));
        }
      }
    }
    return originalSetHeader(name, value);
  };

  next();
});
app.use(helmet({
  contentSecurityPolicy: {
    useDefaults: true,
    directives: {
      'script-src': ["'self'", "'unsafe-inline'", 'https://esm.sh', 'https://unpkg.com'],
      'style-src': ["'self'", "'unsafe-inline'"],
      'img-src': ["'self'", 'data:', 'https:', 'http:'],
      'form-action': ['*'],
    },
  },
}));

const formParser = express.urlencoded({ extended: false });
const jsonParser = express.json({ limit: '1mb' });
const web = express.Router();

web.get('/health', (_req, res) => {
  res.json({ ok: true, issuer });
});

web.use('/me', (req, res, next) => {
  const origin = normalizeOrigin(req.get('origin') || '');
  if (origin && isCorsOriginAllowed(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type');
    res.setHeader('Access-Control-Allow-Methods', 'GET, PATCH, OPTIONS');
  }
  if (req.method === 'OPTIONS') {
    res.sendStatus(204);
    return;
  }
  next();
});

web.patch('/me', jsonParser, async (req, res) => {
  const token = await resolveAccessToken(req);
  if (!token?.accountId) {
    return res.status(401).json({ error: 'invalid_token' });
  }

  try {
    const updated = updateUserProfile(token.accountId, req.body || {});
    return res.json({
      sub: updated.id,
      preferred_username: updated.username || '',
      email: updated.email || '',
      picture: updated.picture || '',
    });
  } catch (error) {
    return res.status(400).json({ error: error?.message || 'Invalid profile update' });
  }
});

web.use('/app/assets', (req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
  res.setHeader('Access-Control-Allow-Methods', 'GET, HEAD, OPTIONS');
  if (req.method === 'OPTIONS') {
    return res.sendStatus(204);
  }
  next();
});

web.use('/app/assets', express.static(join(publicDir, 'assets')));

web.get(['/', '/app', '/app/callback'], (_req, res) => {
  res.type('html').send(renderTemplate(indexTemplate));
});

web.get(['/authWidget', '/authWidget/callback'], (_req, res) => {
  res.type('html').send(renderTemplate(authWidgetTemplate));
});

web.get('/flow-diagram', (_req, res) => {
  res.type('html').send(renderTemplate(flowDiagramTemplate));
});

web.get('/setup/2fa-qr/:username', async (req, res) => {
  if (!isTwoFactorEnabled()) {
    return res.status(404).json({ error: '2FA is disabled' });
  }

  const setupToken = process.env.SETUP_TOKEN || '';
  const queryToken = String(req.query.token || '');
  const headerToken = req.get('x-setup-token') || '';
  if (!setupToken || (headerToken !== setupToken && queryToken !== setupToken)) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  const adminUser = process.env.ADMIN_USERNAME || 'admin';
  const provided = req.params.username;
  if (provided !== adminUser) {
    return res.status(404).json({ error: 'Not found' });
  }

  const payload = await getQrSetupPayload(provided);
  if (!payload) {
    return res.status(404).json({ error: 'User not found' });
  }

  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.end(renderTotpQrSetup(payload));
});

web.get('/setup/2fa-qr/:username.json', async (req, res) => {
  if (!isTwoFactorEnabled()) {
    return res.status(404).json({ error: '2FA is disabled' });
  }

  const setupToken = process.env.SETUP_TOKEN || '';
  const queryToken = String(req.query.token || '');
  const headerToken = req.get('x-setup-token') || '';
  if (!setupToken || (headerToken !== setupToken && queryToken !== setupToken)) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  const adminUser = process.env.ADMIN_USERNAME || 'admin';
  const provided = req.params.username;
  if (provided !== adminUser) {
    return res.status(404).json({ error: 'Not found' });
  }

  const payload = await getQrSetupPayload(provided);
  if (!payload) {
    return res.status(404).json({ error: 'User not found' });
  }

  res.json(payload);
});

web.get('/interaction/:uid/2fa-qr', async (req, res) => {
  if (!isTwoFactorEnabled()) {
    return res.status(404).json({ error: '2FA is disabled' });
  }

  const { uid } = req.params;
  const token = String(req.query.token || '');
  const pending = getTotpSetupSession(token, uid);
  if (!pending) {
    return res.status(404).json({ error: 'Not found' });
  }

  const user = findUserById(pending.accountId);
  const payload = await buildQrSetupPayload(user);
  if (!payload) {
    return res.status(404).json({ error: 'User not found' });
  }

  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.end(renderTotpQrSetup(payload));
});

web.get('/setup/runtime-config', (req, res) => {
  const setupToken = requireSetupToken(req, res);
  if (!setupToken) return;

  res.json({
    twoFactorEnabled: isTwoFactorEnabled(),
    consentEnabled: isConsentEnabled(),
    googleOAuthEnabled: isGoogleOAuthEnabled(),
    passkeyEnabled: isPasskeyEnabled(),
    confirmLogout: isConfirmLogoutEnabled(),
    googleConfigured,
    passkeyRpId: getPasskeyRpId(req),
    passkeyOrigin: getPasskeyOrigin(req),
  });
});

web.post('/setup/runtime-config', formParser, (req, res) => {
  const setupToken = requireSetupToken(req, res);
  if (!setupToken) return;

  if (!Object.hasOwn(req.body, 'twoFactorEnabled')) {
    if (!Object.hasOwn(req.body, 'consentEnabled') && !Object.hasOwn(req.body, 'googleOAuthEnabled') && !Object.hasOwn(req.body, 'passkeyEnabled') && !Object.hasOwn(req.body, 'confirmLogout')) {
      return res.status(400).json({ error: 'twoFactorEnabled or consentEnabled or googleOAuthEnabled or passkeyEnabled or confirmLogout is required' });
    }
  }

  if (Object.hasOwn(req.body, 'twoFactorEnabled')) {
    runtimeConfig.twoFactorEnabled = parseBooleanFlag(req.body.twoFactorEnabled, runtimeConfig.twoFactorEnabled);
  }
  if (Object.hasOwn(req.body, 'consentEnabled')) {
    runtimeConfig.consentEnabled = parseBooleanFlag(req.body.consentEnabled, runtimeConfig.consentEnabled);
  }
  if (Object.hasOwn(req.body, 'googleOAuthEnabled')) {
    runtimeConfig.googleOAuthEnabled = parseBooleanFlag(req.body.googleOAuthEnabled, runtimeConfig.googleOAuthEnabled);
  }
  if (Object.hasOwn(req.body, 'passkeyEnabled')) {
    runtimeConfig.passkeyEnabled = parseBooleanFlag(req.body.passkeyEnabled, runtimeConfig.passkeyEnabled);
  }
  if (Object.hasOwn(req.body, 'confirmLogout')) {
    runtimeConfig.confirmLogout = parseBooleanFlag(req.body.confirmLogout, runtimeConfig.confirmLogout);
  }
  res.json({
    ok: true,
    twoFactorEnabled: isTwoFactorEnabled(),
    consentEnabled: isConsentEnabled(),
    googleOAuthEnabled: isGoogleOAuthEnabled(),
    passkeyEnabled: isPasskeyEnabled(),
    confirmLogout: isConfirmLogoutEnabled(),
    googleConfigured,
    passkeyRpId: getPasskeyRpId(req),
    passkeyOrigin: getPasskeyOrigin(req),
  });
});

web.get('/setup/oidc-store', (req, res) => {
  const setupToken = requireSetupToken(req, res);
  if (!setupToken) return;
  res.json(listOidcStoreOverview());
});

web.post('/setup/oidc-store/session/:uid/revoke', (req, res) => {
  const setupToken = requireSetupToken(req, res);
  if (!setupToken) return;

  const uid = String(req.params.uid || '').trim();
  if (!uid) {
    res.status(400).json({ error: 'session uid is required' });
    return;
  }

  const deleted = revokeOidcBySessionUid(uid);
  res.json({ ok: true, deleted });
});

web.post('/setup/oidc-store/grant/:id/revoke', (req, res) => {
  const setupToken = requireSetupToken(req, res);
  if (!setupToken) return;

  const grantId = String(req.params.id || '').trim();
  if (!grantId) {
    res.status(400).json({ error: 'grant id is required' });
    return;
  }

  const deleted = revokeOidcByGrantId(grantId);
  res.json({ ok: true, deleted });
});

web.post('/setup/oidc-store/record/delete', jsonParser, (req, res) => {
  const setupToken = requireSetupToken(req, res);
  if (!setupToken) return;

  const model = String(req.body?.model || '').trim();
  const id = String(req.body?.id || '').trim();
  if (!model || !id) {
    res.status(400).json({ error: 'model and id are required' });
    return;
  }

  const removed = removeOidcRecord(model, id);
  res.json({ ok: true, removed });
});

function renderOidcSessionsPage(res, setupToken, {
  notice = '',
  error = '',
} = {}) {
  res.type('html').send(renderOidcSessionsAdmin({
    basePath,
    setupToken,
    store: listOidcStoreOverview(),
    notice,
    error,
  }));
}

function parseUriTextarea(value) {
  return String(value || '')
    .split(/\r?\n|,/g)
    .map((item) => item.trim())
    .filter(Boolean);
}

function renderRedirectConfigPage(res, setupToken, {
  selectedClientId = '',
  isNew = false,
  notice = '',
  error = '',
  formValues = {},
  createFormValues = {},
} = {}) {
  const clients = getClients();
  const knownRedirectUris = [...new Set(
    clients.flatMap((client) => Array.isArray(client?.redirect_uris) ? client.redirect_uris : []),
  )];
  const knownPostLogoutRedirectUris = [...new Set(
    clients.flatMap((client) => Array.isArray(client?.post_logout_redirect_uris) ? client.post_logout_redirect_uris : []),
  )];
  const selectedClient = isNew
    ? null
    : (clients.find((client) => client.client_id === selectedClientId) || clients[0] || null);
  const values = {
    client_id: String(formValues.client_id ?? selectedClient?.client_id ?? ''),
    client_kind: String(formValues.client_kind ?? selectedClient?.client_kind ?? 'browser'),
    token_endpoint_auth_method: String(formValues.token_endpoint_auth_method ?? selectedClient?.token_endpoint_auth_method ?? 'none'),
    client_secret: String(formValues.client_secret ?? selectedClient?.client_secret ?? ''),
    api_key: String(formValues.api_key ?? selectedClient?.api_key ?? selectedClient?.client_secret ?? ''),
    scope: String(formValues.scope ?? selectedClient?.scope ?? 'openid profile email offline_access'),
    grant_types: Array.isArray(formValues.grant_types)
      ? formValues.grant_types.join('\n')
      : String(formValues.grant_types ?? (selectedClient?.grant_types || []).join('\n')),
    response_types: Array.isArray(formValues.response_types)
      ? formValues.response_types.join('\n')
      : String(formValues.response_types ?? (selectedClient?.response_types || []).join('\n')),
    redirect_uris: Array.isArray(formValues.redirect_uris)
      ? formValues.redirect_uris.join('\n')
      : (formValues.redirect_uris ?? (selectedClient?.redirect_uris || []).join('\n')),
    post_logout_redirect_uris: Array.isArray(formValues.post_logout_redirect_uris)
      ? formValues.post_logout_redirect_uris.join('\n')
      : (formValues.post_logout_redirect_uris ?? (selectedClient?.post_logout_redirect_uris || []).join('\n')),
  };
  const createValues = {
    client_id: String(createFormValues.client_id ?? ''),
    client_kind: String(createFormValues.client_kind ?? 'browser'),
    token_endpoint_auth_method: String(createFormValues.token_endpoint_auth_method ?? 'none'),
    client_secret: String(createFormValues.client_secret ?? ''),
    api_key: String(createFormValues.api_key ?? ''),
    scope: String(createFormValues.scope ?? 'openid profile email offline_access'),
    grant_types: Array.isArray(createFormValues.grant_types)
      ? createFormValues.grant_types.join('\n')
      : String(createFormValues.grant_types ?? 'authorization_code\nrefresh_token'),
    response_types: Array.isArray(createFormValues.response_types)
      ? createFormValues.response_types.join('\n')
      : String(createFormValues.response_types ?? 'code'),
    redirect_uris: Array.isArray(createFormValues.redirect_uris)
      ? createFormValues.redirect_uris.join('\n')
      : String(createFormValues.redirect_uris ?? knownRedirectUris.join('\n')),
    post_logout_redirect_uris: Array.isArray(createFormValues.post_logout_redirect_uris)
      ? createFormValues.post_logout_redirect_uris.join('\n')
      : String(createFormValues.post_logout_redirect_uris ?? knownPostLogoutRedirectUris.join('\n')),
  };

  res.type('html').send(renderRedirectConfigAdmin({
    basePath,
    setupToken,
    clients,
    isNew,
    selectedClientId: selectedClient?.client_id || '',
    selectedClient,
    values,
    createValues,
    notice,
    error,
  }));
}

web.get('/setup/oidc-sessions', (req, res) => {
  const setupToken = requireSetupToken(req, res);
  if (!setupToken) return;
  renderOidcSessionsPage(res, setupToken);
});

web.post('/setup/oidc-sessions/session/:uid/revoke', (req, res) => {
  const setupToken = requireSetupToken(req, res);
  if (!setupToken) return;
  const uid = String(req.params.uid || '').trim();
  if (!uid) {
    renderOidcSessionsPage(res, setupToken, { error: 'Session UID is required' });
    return;
  }
  const deleted = revokeOidcBySessionUid(uid);
  renderOidcSessionsPage(res, setupToken, { notice: `Session ${uid} revoked (${deleted} records removed).` });
});

web.post('/setup/oidc-sessions/grant/:id/revoke', (req, res) => {
  const setupToken = requireSetupToken(req, res);
  if (!setupToken) return;
  const grantId = String(req.params.id || '').trim();
  if (!grantId) {
    renderOidcSessionsPage(res, setupToken, { error: 'Grant ID is required' });
    return;
  }
  const deleted = revokeOidcByGrantId(grantId);
  renderOidcSessionsPage(res, setupToken, { notice: `Grant ${grantId} revoked (${deleted} records removed).` });
});

web.post('/setup/oidc-sessions/client-credentials/:id/revoke', (req, res) => {
  const setupToken = requireSetupToken(req, res);
  if (!setupToken) return;
  const tokenId = String(req.params.id || '').trim();
  if (!tokenId) {
    renderOidcSessionsPage(res, setupToken, { error: 'Client credentials token ID is required' });
    return;
  }
  const removed = revokeClientCredentialsToken(tokenId);
  if (!removed) {
    renderOidcSessionsPage(res, setupToken, { error: `Client credentials token ${tokenId} not found` });
    return;
  }
  renderOidcSessionsPage(res, setupToken, { notice: `Client credentials token ${tokenId} revoked.` });
});

web.get('/setup/config', (req, res) => {
  const setupToken = requireSetupToken(req, res);
  if (!setupToken) return;
  const selectedClientId = String(req.query.client_id || '').trim();
  const isNew = String(req.query.new || '').trim() === '1';
  renderRedirectConfigPage(res, setupToken, { selectedClientId, isNew });
});

web.post('/setup/config', formParser, (req, res) => {
  const setupToken = requireSetupToken(req, res);
  if (!setupToken) return;

  const clientId = String(req.body.client_id || '').trim();
  const redirectUris = parseUriTextarea(req.body.redirect_uris);
  const postLogoutRedirectUris = parseUriTextarea(req.body.post_logout_redirect_uris);

  try {
    updateClientRedirectUris(clientId, {
      redirectUris,
      postLogoutRedirectUris,
    });
    renderRedirectConfigPage(res, setupToken, {
      selectedClientId: clientId,
      notice: `Client ${clientId} updated`,
    });
  } catch (error) {
    renderRedirectConfigPage(res, setupToken, {
      selectedClientId: clientId,
      error: error?.message || 'Unable to update redirect URI configuration',
      formValues: {
        redirect_uris: redirectUris,
        post_logout_redirect_uris: postLogoutRedirectUris,
      },
    });
  }
});

web.post('/setup/config/client/create', formParser, (req, res) => {
  const setupToken = requireSetupToken(req, res);
  if (!setupToken) return;

  const payload = {
    client_id: String(req.body.client_id || '').trim(),
    client_kind: String(req.body.client_kind || 'browser').trim() || 'browser',
    token_endpoint_auth_method: String(req.body.token_endpoint_auth_method || 'none').trim() || 'none',
    client_secret: String(req.body.client_secret || ''),
    api_key: String(req.body.api_key || ''),
    scope: String(req.body.scope || '').trim(),
    grant_types: parseUriTextarea(req.body.grant_types),
    response_types: parseUriTextarea(req.body.response_types),
    redirect_uris: parseUriTextarea(req.body.redirect_uris),
    post_logout_redirect_uris: parseUriTextarea(req.body.post_logout_redirect_uris),
  };

  try {
    const created = createClient(payload);
    renderRedirectConfigPage(res, setupToken, {
      selectedClientId: created.client_id,
      notice: `Client ${created.client_id} created`,
    });
  } catch (error) {
    renderRedirectConfigPage(res, setupToken, {
      isNew: true,
      selectedClientId: '',
      error: error?.message || 'Unable to create client',
      createFormValues: payload,
    });
  }
});

web.post('/setup/config/client/:id/update', formParser, (req, res) => {
  const setupToken = requireSetupToken(req, res);
  if (!setupToken) return;

  const clientId = String(req.params.id || '').trim();
  const payload = {
    client_kind: String(req.body.client_kind || 'browser').trim() || 'browser',
    token_endpoint_auth_method: String(req.body.token_endpoint_auth_method || 'none').trim() || 'none',
    client_secret: String(req.body.client_secret || ''),
    api_key: String(req.body.api_key || ''),
    scope: String(req.body.scope || '').trim(),
    grant_types: parseUriTextarea(req.body.grant_types),
    response_types: parseUriTextarea(req.body.response_types),
    redirect_uris: parseUriTextarea(req.body.redirect_uris),
    post_logout_redirect_uris: parseUriTextarea(req.body.post_logout_redirect_uris),
  };

  try {
    updateClient(clientId, payload);
    renderRedirectConfigPage(res, setupToken, {
      selectedClientId: clientId,
      notice: `Client ${clientId} updated`,
    });
  } catch (error) {
    const currentClient = getClients().find((client) => client.client_id === clientId) || null;
    const redirectUrisForForm = payload.redirect_uris.length > 0
      ? payload.redirect_uris
      : (Array.isArray(currentClient?.redirect_uris) ? currentClient.redirect_uris : []);
    const postLogoutRedirectUrisForForm = payload.post_logout_redirect_uris.length > 0
      ? payload.post_logout_redirect_uris
      : (Array.isArray(currentClient?.post_logout_redirect_uris) ? currentClient.post_logout_redirect_uris : []);
    renderRedirectConfigPage(res, setupToken, {
      selectedClientId: clientId,
      error: error?.message || 'Unable to update client',
      formValues: {
        client_id: clientId,
        ...payload,
        redirect_uris: redirectUrisForForm,
        post_logout_redirect_uris: postLogoutRedirectUrisForForm,
      },
    });
  }
});

web.post('/setup/config/client/:id/delete', formParser, (req, res) => {
  const setupToken = requireSetupToken(req, res);
  if (!setupToken) return;

  const clientId = String(req.params.id || '').trim();
  try {
    deleteClient(clientId);
    renderRedirectConfigPage(res, setupToken, {
      notice: `Client ${clientId} deleted`,
    });
  } catch (error) {
    renderRedirectConfigPage(res, setupToken, {
      selectedClientId: clientId,
      error: error?.message || 'Unable to delete client',
    });
  }
});

web.post('/setup/passkeys/:username/options', jsonParser, async (req, res) => {
  if (!isPasskeyEnabled()) {
    return res.status(404).json({ error: 'Passkey is disabled' });
  }

  const setupToken = requireSetupToken(req, res);
  if (!setupToken) return;

  const username = String(req.params.username || '').trim();
  const user = findUserByUsername(username);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }
  if (Array.isArray(user.passkeys) && user.passkeys.length > 0) {
    clearUserPasskeys(user.id);
  }

  try {
    const options = await generateRegistrationOptions({
      rpName: passkeyRpName,
      rpID: getPasskeyRpId(req),
      userID: Buffer.from(user.id, 'utf8'),
      userName: user.username,
      userDisplayName: user.email || user.username,
      timeout: 60_000,
      attestationType: 'none',
      authenticatorSelection: {
        residentKey: 'preferred',
        userVerification: 'preferred',
      },
      excludeCredentials: (user.passkeys || []).map((passkey) => ({
        id: passkey.id,
        transports: Array.isArray(passkey.transports) ? passkey.transports : [],
      })),
    });

    const token = createPasskeyRegistrationSession(username, options.challenge);
    return res.json({
      token,
      publicKey: options,
    });
  } catch (error) {
    return res.status(400).json({ error: error?.message || 'Unable to generate passkey registration options' });
  }
});

web.post('/setup/passkeys/:username/verify', jsonParser, async (req, res) => {
  if (!isPasskeyEnabled()) {
    return res.status(404).json({ error: 'Passkey is disabled' });
  }

  const setupToken = requireSetupToken(req, res);
  if (!setupToken) return;

  const username = String(req.params.username || '').trim();
  const user = findUserByUsername(username);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }

  const token = String(req.body?.token || '');
  const credential = req.body?.credential;
  if (!token || !credential) {
    return res.status(400).json({ error: 'token and credential are required' });
  }

  const pending = consumePasskeyRegistrationSession(token, username);
  if (!pending) {
    return res.status(401).json({ error: 'Passkey registration session expired' });
  }

  try {
    const verification = await verifyRegistrationResponse({
      response: credential,
      expectedChallenge: pending.challenge,
      expectedOrigin: getPasskeyOrigin(req),
      expectedRPID: getPasskeyRpId(req),
      requireUserVerification: false,
    });

    if (!verification.verified || !verification.registrationInfo) {
      return res.status(401).json({ error: 'Passkey registration verification failed' });
    }

    const registrationInfo = verification.registrationInfo;
    const credentialInfo = registrationInfo.credential || {};
    const credentialId = toBase64Url(credentialInfo.id || registrationInfo.credentialID);
    const publicKey = toBase64Url(credentialInfo.publicKey || registrationInfo.credentialPublicKey);
    const counter = Number(credentialInfo.counter ?? registrationInfo.counter ?? 0);
    const transports = Array.isArray(credentialInfo.transports) ? credentialInfo.transports : [];
    const deviceType = registrationInfo.credentialDeviceType || credentialInfo.deviceType || '';
    const backedUp = Boolean(registrationInfo.credentialBackedUp ?? credentialInfo.backedUp);

    if (!credentialId || !publicKey) {
      return res.status(400).json({ error: 'Invalid passkey registration payload' });
    }

    upsertUserPasskey(user.id, {
      id: credentialId,
      public_key: publicKey,
      counter,
      transports,
      device_type: deviceType,
      backed_up: backedUp,
    });

    return res.json({
      ok: true,
      username: user.username,
      credentialId,
    });
  } catch (error) {
    return res.status(400).json({ error: error?.message || 'Passkey registration verification failed' });
  }
});

web.get('/setup/users', (req, res) => {
  const setupToken = requireSetupToken(req, res);
  if (!setupToken) return;

  const users = listUsers();
  const selectedUser = users[0] || null;
  res.type('html').send(renderUsersAdmin({
    basePath,
    setupToken,
    users,
    selectedUser,
  }));
});

web.get('/setup/users/new', (req, res) => {
  const setupToken = requireSetupToken(req, res);
  if (!setupToken) return;

  res.type('html').send(renderUsersAdmin({
    basePath,
    setupToken,
    users: listUsers(),
    isNew: true,
  }));
});

web.get('/setup/users/:id', (req, res) => {
  const setupToken = requireSetupToken(req, res);
  if (!setupToken) return;

  const selectedUser = findUserById(req.params.id);
  if (!selectedUser) {
    return res.status(404).type('html').send(renderUsersAdmin({
      basePath,
      setupToken,
      users: listUsers(),
      error: 'User not found',
      isNew: true,
    }));
  }

  res.type('html').send(renderUsersAdmin({
    basePath,
    setupToken,
    users: listUsers(),
    selectedUser,
  }));
});

web.post('/setup/users', formParser, async (req, res) => {
  const setupToken = requireSetupToken(req, res);
  if (!setupToken) return;

  try {
    const created = await createUser(req.body);
    res.redirect(resolvePath(basePath, `/setup/users/${encodeURIComponent(created.id)}?token=${encodeURIComponent(setupToken)}`));
  } catch (error) {
    res.status(400).type('html').send(renderUsersAdmin({
      basePath,
      setupToken,
      users: listUsers(),
      isNew: true,
      error: error.message || 'Unable to create user',
      formValues: req.body,
    }));
  }
});

web.post('/setup/users/:id', formParser, async (req, res) => {
  const setupToken = requireSetupToken(req, res);
  if (!setupToken) return;

  try {
    const updated = await updateUser(req.params.id, req.body);
    res.type('html').send(renderUsersAdmin({
      basePath,
      setupToken,
      users: listUsers(),
      selectedUser: updated,
      notice: 'User updated',
    }));
  } catch (error) {
    const selectedUser = findUserById(req.params.id);
    res.status(400).type('html').send(renderUsersAdmin({
      basePath,
      setupToken,
      users: listUsers(),
      selectedUser,
      error: error.message || 'Unable to update user',
      formValues: req.body,
    }));
  }
});

web.post('/setup/users/:id/delete', formParser, (req, res) => {
  const setupToken = requireSetupToken(req, res);
  if (!setupToken) return;

  try {
    deleteUser(req.params.id);
    res.redirect(resolvePath(basePath, `/setup/users?token=${encodeURIComponent(setupToken)}`));
  } catch (error) {
    const selectedUser = findUserById(req.params.id);
    res.status(400).type('html').send(renderUsersAdmin({
      basePath,
      setupToken,
      users: listUsers(),
      selectedUser,
      error: error.message || 'Unable to delete user',
    }));
  }
});

web.get('/interaction/:uid/continue', async (req, res, next) => {
  try {
    const { uid } = req.params;
    const token = String(req.query.token || '');
    const pending = consumeInteractionCallbackSession(token, uid);

    if (!pending) {
      res.status(401).setHeader('Content-Type', 'text/html; charset=utf-8');
      res.end(renderLoginPage({
        basePath,
        uid,
        twoFactorEnabled: isTwoFactorEnabled(),
        error: 'Callback session expired. Sign in again.',
        googleLoginUrl: getGoogleLoginUrl(uid),
        googleRegisterUrl: getGoogleRegisterUrl(uid),
      }));
      return;
    }

    await provider.interactionFinished(req, res, pending.result, {
      mergeWithLastSubmission: pending.mergeWithLastSubmission,
    });
  } catch (err) {
    if (isMissingInteractionSession(err)) {
      respondExpiredSession(res);
      return;
    }
    next(err);
  }
});

web.get('/interaction/:uid/login/google/callback', async (req, res, next) => {
  try {
    const { uid } = req.params;
    const token = String(req.query.token || '');
    const pending = consumeGoogleCallbackSession(token, uid);

    if (!pending) {
      res.status(401).setHeader('Content-Type', 'text/html; charset=utf-8');
      res.end(renderLoginPage({
        basePath,
        uid,
        twoFactorEnabled: isTwoFactorEnabled(),
        error: 'Google session expired. Sign in again.',
        googleLoginUrl: getGoogleLoginUrl(uid),
        googleRegisterUrl: getGoogleRegisterUrl(uid),
      }));
      return;
    }

    const user = findUserById(pending.accountId);
    if (!user) {
      res.status(401).setHeader('Content-Type', 'text/html; charset=utf-8');
      res.end(renderLoginPage({
        basePath,
        uid,
        twoFactorEnabled: isTwoFactorEnabled(),
        error: 'Unknown account. Sign in again.',
        googleLoginUrl: getGoogleLoginUrl(uid),
        googleRegisterUrl: getGoogleRegisterUrl(uid),
      }));
      return;
    }

    const isRegisterIntent = pending.mode === 'register';

    if (!isTotpRequired(user)) {
      if (isRegisterIntent && isPasskeyEnabled() && !hasPasskeys(user)) {
        await renderPasskeyOnboardingForUser(req, res, uid, user);
        return;
      }
      await finishLogin(req, res, user.id);
      return;
    }

    const challenge = createTotpChallenge(uid, user.id, isRegisterIntent ? 'register' : 'login');
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.end(renderLoginPage({
      basePath,
      uid,
      twoFactorEnabled: isTwoFactorEnabled(),
      username: user.username,
      googleChallenge: challenge,
      googleAccountLabel: user.email || user.username,
      qrSetupUrl: getInteractionQrSetupUrl(uid, user.id),
    }));
  } catch (err) {
    if (isMissingInteractionSession(err)) {
      respondExpiredSession(res);
      return;
    }
    next(err);
  }
});

web.get('/interaction/:uid', async (req, res, next) => {
  try {
    const details = await provider.interactionDetails(req, res);
    const { uid, prompt, params } = details;

    if (prompt.name === 'login') {
      const backUrl = getInteractionBackUrl(params);
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.end(renderLoginPage({
        basePath,
        uid,
        backUrl,
        twoFactorEnabled: isTwoFactorEnabled(),
        googleLoginUrl: getGoogleLoginUrl(uid),
        googleRegisterUrl: getGoogleRegisterUrl(uid),
      }));
      return;
    }

    if (prompt.name === 'consent') {
      if (!isConsentEnabled()) {
        const interactionDetails = await provider.interactionDetails(req, res);
        const { prompt: { details: consentDetails } } = interactionDetails;
        const grant = interactionDetails.grantId
          ? await provider.Grant.find(interactionDetails.grantId)
          : new provider.Grant({
              accountId: interactionDetails.session.accountId,
              clientId: interactionDetails.params.client_id,
            });

        if (consentDetails.missingOIDCScope) {
          grant.addOIDCScope(consentDetails.missingOIDCScope.join(' '));
        }
        if (consentDetails.missingOIDCClaims) {
          grant.addOIDCClaims(consentDetails.missingOIDCClaims);
        }
        if (consentDetails.missingResourceScopes) {
          for (const [indicator, scopes] of Object.entries(consentDetails.missingResourceScopes)) {
            grant.addResourceScope(indicator, scopes.join(' '));
          }
        }

        const grantId = await grant.save();
        await finishInteraction(req, res, { consent: { grantId } }, {
          mergeWithLastSubmission: true,
          callbackStage: 'consent_allow',
          callbackStatus: 'success',
        });
        return;
      }

      const client = await provider.Client.find(params.client_id);
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.end(renderConsent({ basePath, uid, clientName: client?.clientName || params.client_id, scope: params.scope }));
      return;
    }

    res.status(400).send('Unsupported interaction');
  } catch (err) {
    next(err);
  }
});

web.get('/interaction/:uid/register', async (req, res, next) => {
  try {
    const { uid } = req.params;
    const details = await provider.interactionDetails(req, res);
    const backUrl = getInteractionBackUrl(details?.params);
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.end(renderRegisterPage({
      basePath,
      uid,
      backUrl,
      googleRegisterUrl: getGoogleRegisterUrl(uid),
    }));
  } catch (err) {
    if (isMissingInteractionSession(err)) {
      respondExpiredSession(res);
      return;
    }
    next(err);
  }
});

web.post('/interaction/:uid/register', formParser, loginLimiter, async (req, res, next) => {
  try {
    const { uid } = req.params;
    const details = await provider.interactionDetails(req, res);
    const backUrl = getInteractionBackUrl(details?.params);
    const username = String(req.body?.username || '').trim();
    const password = String(req.body?.password || '');
    const email = String(req.body?.email || '').trim();

    if (!username || !password) {
      res.status(400).setHeader('Content-Type', 'text/html; charset=utf-8');
      res.end(renderRegisterPage({
        basePath,
        uid,
        backUrl,
        googleRegisterUrl: getGoogleRegisterUrl(uid),
        error: 'Username and password are required',
        formValues: { username, email },
      }));
      return;
    }

    let user;
    try {
      user = await createUser({
        username,
        password,
        email,
        auth_provider: 'local',
      });
    } catch (error) {
      res.status(400).setHeader('Content-Type', 'text/html; charset=utf-8');
      res.end(renderRegisterPage({
        basePath,
        uid,
        backUrl,
        googleRegisterUrl: getGoogleRegisterUrl(uid),
        error: error?.message || 'Unable to create user',
        formValues: { username, email },
      }));
      return;
    }

    if (isPasskeyEnabled()) {
      await renderPasskeyOnboardingForUser(req, res, uid, user);
      return;
    }

    await finishLogin(req, res, user.id);
  } catch (err) {
    if (isMissingInteractionSession(err)) {
      respondExpiredSession(res);
      return;
    }
    next(err);
  }
});

web.post('/interaction/:uid/passkey/onboarding/options', jsonParser, async (req, res) => {
  if (!isPasskeyEnabled()) {
    return res.status(404).json({ error: 'Passkey is disabled' });
  }

  const { uid } = req.params;
  const token = String(req.body?.token || '');
  const pending = getPasskeyOnboardingSession(token, uid);
  if (!pending) {
    return res.status(401).json({ error: 'Passkey onboarding session expired' });
  }
  const user = findUserById(pending.accountId);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }
  if (Array.isArray(user.passkeys) && user.passkeys.length > 0) {
    clearUserPasskeys(user.id);
  }

  try {
    const options = await generateRegistrationOptions({
      rpName: passkeyRpName,
      rpID: getPasskeyRpId(req),
      userID: Buffer.from(user.id, 'utf8'),
      userName: user.username,
      userDisplayName: user.email || user.username,
      timeout: 60_000,
      attestationType: 'none',
      authenticatorSelection: {
        residentKey: 'preferred',
        userVerification: 'preferred',
      },
      excludeCredentials: (user.passkeys || []).map((passkey) => ({
        id: passkey.id,
        transports: Array.isArray(passkey.transports) ? passkey.transports : [],
      })),
    });
    pending.challenge = options.challenge;
    pending.expiresAt = Date.now() + 5 * 60 * 1000;
    passkeyOnboardingSessions.set(token, pending);
    return res.json({ token, publicKey: options });
  } catch (error) {
    return res.status(400).json({ error: error?.message || 'Unable to start passkey onboarding' });
  }
});

web.post('/interaction/:uid/passkey/onboarding/verify', jsonParser, async (req, res) => {
  if (!isPasskeyEnabled()) {
    return res.status(404).json({ error: 'Passkey is disabled' });
  }

  const { uid } = req.params;
  const token = String(req.body?.token || '');
  const credential = req.body?.credential;
  const pending = getPasskeyOnboardingSession(token, uid);
  if (!pending) {
    return res.status(401).json({ error: 'Passkey onboarding session expired' });
  }
  const user = findUserById(pending.accountId);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }
  if (!credential || !pending.challenge) {
    return res.status(400).json({ error: 'token and credential are required' });
  }

  try {
    const verification = await verifyRegistrationResponse({
      response: credential,
      expectedChallenge: pending.challenge,
      expectedOrigin: getPasskeyOrigin(req),
      expectedRPID: getPasskeyRpId(req),
      requireUserVerification: false,
    });

    if (!verification.verified || !verification.registrationInfo) {
      return res.status(401).json({ error: 'Passkey registration verification failed' });
    }

    const registrationInfo = verification.registrationInfo;
    const credentialInfo = registrationInfo.credential || {};
    const credentialId = toBase64Url(credentialInfo.id || registrationInfo.credentialID);
    const publicKey = toBase64Url(credentialInfo.publicKey || registrationInfo.credentialPublicKey);
    const counter = Number(credentialInfo.counter ?? registrationInfo.counter ?? 0);
    const transports = Array.isArray(credentialInfo.transports) ? credentialInfo.transports : [];
    const deviceType = registrationInfo.credentialDeviceType || credentialInfo.deviceType || '';
    const backedUp = Boolean(registrationInfo.credentialBackedUp ?? credentialInfo.backedUp);

    if (!credentialId || !publicKey) {
      return res.status(400).json({ error: 'Invalid passkey registration payload' });
    }

    upsertUserPasskey(user.id, {
      id: credentialId,
      public_key: publicKey,
      counter,
      transports,
      device_type: deviceType,
      backed_up: backedUp,
    });

    return res.json({
      ok: true,
      redirectTo: resolvePath(basePath, `/interaction/${encodeURIComponent(uid)}/passkey/onboarding/continue?token=${encodeURIComponent(token)}`),
    });
  } catch (error) {
    return res.status(400).json({ error: error?.message || 'Passkey registration failed' });
  }
});

web.get('/interaction/:uid/passkey/onboarding/continue', async (req, res, next) => {
  try {
    const { uid } = req.params;
    const token = String(req.query.token || '');
    const pending = consumePasskeyOnboardingSession(token, uid);
    if (!pending) {
      res.status(401).setHeader('Content-Type', 'text/html; charset=utf-8');
      res.end(renderLoginPage({
        basePath,
        uid,
        twoFactorEnabled: isTwoFactorEnabled(),
        error: 'Passkey onboarding session expired. Sign in again.',
        googleLoginUrl: getGoogleLoginUrl(uid),
        googleRegisterUrl: getGoogleRegisterUrl(uid),
      }));
      return;
    }
    await finishLogin(req, res, pending.accountId);
  } catch (err) {
    if (isMissingInteractionSession(err)) {
      respondExpiredSession(res);
      return;
    }
    next(err);
  }
});

web.post('/interaction/:uid/passkey/options', jsonParser, async (req, res) => {
  if (!isPasskeyEnabled()) {
    return res.status(404).json({ error: 'Passkey is disabled' });
  }

  const { uid } = req.params;
  try {
    await provider.interactionDetails(req, res);
  } catch {
    return res.status(401).json({ error: 'Interaction session expired' });
  }

  const username = String(req.body?.username || '').trim();
  if (!username) {
    return res.status(400).json({ error: 'Username is required for passkey sign-in' });
  }

  const user = findUserByUsername(username);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }

  const allowCredentials = (user.passkeys || []).map((passkey) => ({
    id: passkey.id,
    transports: Array.isArray(passkey.transports) ? passkey.transports : [],
  }));

  if (allowCredentials.length === 0) {
    return res.status(400).json({ error: `No passkey credentials are registered for ${username}` });
  }

  const options = await generateAuthenticationOptions({
    rpID: getPasskeyRpId(req),
    userVerification: 'preferred',
    timeout: 60_000,
    allowCredentials,
  });
  const token = createPasskeyAuthSession(uid, options.challenge);
  return res.json({
    token,
    publicKey: options,
  });
});

web.post('/interaction/:uid/passkey/enroll', jsonParser, loginLimiter, async (req, res) => {
  if (!isPasskeyEnabled()) {
    return res.status(404).json({ error: 'Passkey is disabled' });
  }

  const { uid } = req.params;
  try {
    await provider.interactionDetails(req, res);
  } catch {
    return res.status(401).json({ error: 'Interaction session expired' });
  }

  const username = String(req.body?.username || '').trim();
  const password = String(req.body?.password || '');
  const otp = String(req.body?.otp || '').trim();

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required to enroll passkey' });
  }

  const user = findUserByUsername(username);
  if (!user || !user.password_hash) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const passwordOk = await argon2.verify(user.password_hash, password, {
    type: argon2.argon2id,
  });
  if (!passwordOk) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  if (isTotpRequired(user) && !verifyTotpToken(user, otp)) {
    return res.status(401).json({ error: otp ? 'Invalid verification code' : 'Authenticator code is required' });
  }

  const token = createPasskeyOnboardingSession(uid, user.id);
  return res.json({
    ok: true,
    redirectTo: resolvePath(basePath, `/interaction/${encodeURIComponent(uid)}/passkey/onboarding?token=${encodeURIComponent(token)}`),
  });
});

web.get('/interaction/:uid/passkey/onboarding', async (req, res, next) => {
  try {
    if (!isPasskeyEnabled()) {
      res.status(404).send('Passkey is disabled');
      return;
    }

    const { uid } = req.params;
    const token = String(req.query.token || '');
    const pending = getPasskeyOnboardingSession(token, uid);
    if (!pending) {
      res.status(401).setHeader('Content-Type', 'text/html; charset=utf-8');
      res.end(renderLoginPage({
        basePath,
        uid,
        twoFactorEnabled: isTwoFactorEnabled(),
        error: 'Passkey onboarding session expired. Sign in again.',
        googleLoginUrl: getGoogleLoginUrl(uid),
        googleRegisterUrl: getGoogleRegisterUrl(uid),
      }));
      return;
    }

    const user = findUserById(pending.accountId);
    if (!user) {
      res.status(401).setHeader('Content-Type', 'text/html; charset=utf-8');
      res.end(renderLoginPage({
        basePath,
        uid,
        twoFactorEnabled: isTwoFactorEnabled(),
        error: 'Unknown account. Sign in again.',
        googleLoginUrl: getGoogleLoginUrl(uid),
        googleRegisterUrl: getGoogleRegisterUrl(uid),
      }));
      return;
    }

    const details = await provider.interactionDetails(req, res);
    const backUrl = getInteractionBackUrl(details?.params);
    res.status(200).setHeader('Content-Type', 'text/html; charset=utf-8');
    res.end(renderPasskeyOnboarding({
      basePath,
      uid,
      token,
      username: user.username,
      backUrl,
    }));
  } catch (err) {
    if (isMissingInteractionSession(err)) {
      respondExpiredSession(res);
      return;
    }
    next(err);
  }
});

web.post('/interaction/:uid/passkey/verify', jsonParser, async (req, res) => {
  if (!isPasskeyEnabled()) {
    return res.status(404).json({ error: 'Passkey is disabled' });
  }

  const { uid } = req.params;
  const token = String(req.body?.token || '');
  const credential = req.body?.credential;
  if (!token || !credential) {
    return res.status(400).json({ error: 'token and credential are required' });
  }

  const pending = consumePasskeyAuthSession(token, uid);
  if (!pending) {
    return res.status(401).json({ error: 'Passkey session expired' });
  }

  const credentialId = String(credential?.id || '');
  if (!credentialId) {
    return res.status(400).json({ error: 'Missing passkey credential id' });
  }

  const resolved = findPasskeyByCredentialId(credentialId);
  if (!resolved?.user || !resolved?.passkey) {
    return res.status(401).json({ error: 'Unknown passkey credential' });
  }

  try {
    const verification = await verifyAuthenticationResponse({
      response: credential,
      expectedChallenge: pending.challenge,
      expectedOrigin: getPasskeyOrigin(req),
      expectedRPID: getPasskeyRpId(req),
      credential: {
        id: resolved.passkey.id,
        publicKey: fromBase64Url(resolved.passkey.public_key),
        counter: Number(resolved.passkey.counter || 0),
        transports: Array.isArray(resolved.passkey.transports) ? resolved.passkey.transports : [],
      },
      requireUserVerification: false,
    });

    if (!verification.verified) {
      return res.status(401).json({ error: 'Passkey verification failed' });
    }

    const newCounter = Number(verification.authenticationInfo?.newCounter ?? resolved.passkey.counter ?? 0);
    touchUserPasskeyCounter(resolved.user.id, resolved.passkey.id, newCounter);

    const completionToken = isTotpRequired(resolved.user)
      ? createPasskeyCompletionSession(uid, {
          mode: 'totp',
          accountId: resolved.user.id,
          challenge: createTotpChallenge(uid, resolved.user.id),
        })
      : createPasskeyCompletionSession(uid, {
          mode: 'login',
          accountId: resolved.user.id,
        });

    return res.json({
      ok: true,
      redirectTo: resolvePath(basePath, `/interaction/${encodeURIComponent(uid)}/passkey/continue?token=${encodeURIComponent(completionToken)}`),
    });
  } catch (error) {
    return res.status(400).json({ error: error?.message || 'Passkey verification failed' });
  }
});

web.get('/interaction/:uid/passkey/continue', async (req, res, next) => {
  try {
    const { uid } = req.params;
    const token = String(req.query.token || '');
    const pending = consumePasskeyCompletionSession(token, uid);
    if (!pending) {
      res.status(401).setHeader('Content-Type', 'text/html; charset=utf-8');
      res.end(renderLoginPage({
        basePath,
        uid,
        twoFactorEnabled: isTwoFactorEnabled(),
        error: 'Passkey session expired. Sign in again.',
        googleLoginUrl: getGoogleLoginUrl(uid),
        googleRegisterUrl: getGoogleRegisterUrl(uid),
      }));
      return;
    }

    if (pending.mode === 'totp') {
      const user = findUserById(pending.accountId);
      res.status(200).setHeader('Content-Type', 'text/html; charset=utf-8');
      res.end(renderLoginPage({
        basePath,
        uid,
        twoFactorEnabled: isTwoFactorEnabled(),
        username: user?.username || '',
        googleChallenge: pending.challenge,
        googleAccountLabel: user?.email || user?.username || '',
        qrSetupUrl: user ? getInteractionQrSetupUrl(uid, user.id) : '',
      }));
      return;
    }

    await finishLogin(req, res, pending.accountId);
  } catch (err) {
    if (isMissingInteractionSession(err)) {
      respondExpiredSession(res);
      return;
    }
    next(err);
  }
});

web.post('/interaction/:uid/login', formParser, loginLimiter, async (req, res, next) => {
  try {
    const { uid } = req.params;
    const { username = '', password = '', otp = '', challenge = '' } = req.body;

    if (challenge) {
      const pending = consumeTotpChallenge(challenge, uid);
      if (!pending) {
        res.status(401).setHeader('Content-Type', 'text/html; charset=utf-8');
        res.end(renderLoginPage({
          basePath,
          uid,
          twoFactorEnabled: isTwoFactorEnabled(),
          error: 'Session expired. Sign in again.',
          googleLoginUrl: getGoogleLoginUrl(uid),
          googleRegisterUrl: getGoogleRegisterUrl(uid),
        }));
        return;
      }

      const resolvedUser = findUserById(pending.accountId);
      if (!resolvedUser) {
        res.status(401).setHeader('Content-Type', 'text/html; charset=utf-8');
        res.end(renderLoginPage({
          basePath,
          uid,
          twoFactorEnabled: isTwoFactorEnabled(),
          error: 'Unknown account. Sign in again.',
          googleLoginUrl: getGoogleLoginUrl(uid),
          googleRegisterUrl: getGoogleRegisterUrl(uid),
        }));
        return;
      }

      if (!verifyTotpToken(resolvedUser, otp)) {
        const retryChallenge = createTotpChallenge(uid, resolvedUser.id, pending.intent || 'login');
        res.status(401).setHeader('Content-Type', 'text/html; charset=utf-8');
        res.end(renderLoginPage({
          basePath,
          uid,
          twoFactorEnabled: isTwoFactorEnabled(),
          username: resolvedUser.username,
          otp,
          error: 'Invalid verification code',
          googleChallenge: retryChallenge,
          googleAccountLabel: resolvedUser.email || resolvedUser.username,
          qrSetupUrl: getInteractionQrSetupUrl(uid, resolvedUser.id),
        }));
        return;
      }

      if (pending.intent === 'register' && isPasskeyEnabled() && !hasPasskeys(resolvedUser)) {
        await renderPasskeyOnboardingForUser(req, res, uid, resolvedUser);
        return;
      }
      await finishLogin(req, res, resolvedUser.id);
      return;
    }

    const user = findUserByUsername(username.trim());
    if (!user || !user.password_hash) {
      res.status(401).setHeader('Content-Type', 'text/html; charset=utf-8');
      res.end(renderLoginPage({
        basePath,
        uid,
        twoFactorEnabled: isTwoFactorEnabled(),
        username,
        error: 'Invalid credentials',
        googleLoginUrl: getGoogleLoginUrl(uid),
        googleRegisterUrl: getGoogleRegisterUrl(uid),
      }));
      return;
    }

    const passwordOk = await argon2.verify(user.password_hash, password, {
      type: argon2.argon2id,
    });
    if (!passwordOk) {
      res.status(401).setHeader('Content-Type', 'text/html; charset=utf-8');
      res.end(renderLoginPage({
        basePath,
        uid,
        twoFactorEnabled: isTwoFactorEnabled(),
        username,
        error: 'Invalid credentials',
        googleLoginUrl: getGoogleLoginUrl(uid),
        googleRegisterUrl: getGoogleRegisterUrl(uid),
      }));
      return;
    }

    if (isTotpRequired(user)) {
      if (!verifyTotpToken(user, otp)) {
        res.status(401).setHeader('Content-Type', 'text/html; charset=utf-8');
        res.end(renderLoginPage({
          basePath,
          uid,
          twoFactorEnabled: isTwoFactorEnabled(),
          username,
          error: otp ? 'Invalid verification code' : 'Authenticator code is required',
          qrSetupUrl: getInteractionQrSetupUrl(uid, user.id),
          googleLoginUrl: getGoogleLoginUrl(uid),
          googleRegisterUrl: getGoogleRegisterUrl(uid),
        }));
        return;
      }
    }

    await finishLogin(req, res, user.id);
  } catch (err) {
    if (isMissingInteractionSession(err)) {
      respondExpiredSession(res);
      return;
    }
    next(err);
  }
});

web.get('/interaction/:uid/login/google', startGoogleAuth);
web.get('/interaction/:uid/register/google', startGoogleAuth);

web.get(googleCallbackRoutePath, async (req, res, next) => {
  const state = String(req.query.state || '');
  const code = String(req.query.code || '');
  const error = String(req.query.error || '');
  const pending = consumeGoogleState(state);
  const uid = pending?.uid || '';

  try {
    if (!isGoogleOAuthEnabled()) {
      res.status(404).send('Google login is not configured');
      return;
    }

    if (!pending || !uid) {
      res.status(400).send('Invalid Google login state');
      return;
    }

    if (error) {
      res.status(401).setHeader('Content-Type', 'text/html; charset=utf-8');
      res.end(renderLoginPage({
        basePath,
        uid,
        twoFactorEnabled: isTwoFactorEnabled(),
        error: 'Google login was cancelled',
        googleLoginUrl: getGoogleLoginUrl(uid),
        googleRegisterUrl: getGoogleRegisterUrl(uid),
      }));
      return;
    }

    if (!code) {
      res.status(400).setHeader('Content-Type', 'text/html; charset=utf-8');
      res.end(renderLoginPage({
        basePath,
        uid,
        twoFactorEnabled: isTwoFactorEnabled(),
        error: 'Missing Google authorization code',
        googleLoginUrl: getGoogleLoginUrl(uid),
        googleRegisterUrl: getGoogleRegisterUrl(uid),
      }));
      return;
    }

    const tokenSet = await exchangeGoogleCode(code, getGoogleCallbackUrl(req));
    const profile = await fetchGoogleProfile(tokenSet.access_token);
    const user = upsertGoogleUser(profile);
    const callbackToken = createGoogleCallbackSession(uid, user.id, pending.mode || 'login');
    res.redirect(resolvePath(basePath, `/interaction/${encodeURIComponent(uid)}/login/google/callback?token=${encodeURIComponent(callbackToken)}`));
  } catch (err) {
    console.error('Google callback failed', {
      uid,
      message: err?.message,
      stack: err?.stack,
    });

    if (uid) {
      if (isMissingInteractionSession(err)) {
        respondExpiredSession(res);
        return;
      }

      res.status(401).setHeader('Content-Type', 'text/html; charset=utf-8');
      res.end(renderLoginPage({
        basePath,
        uid,
        twoFactorEnabled: isTwoFactorEnabled(),
        error: 'Google login failed',
        googleLoginUrl: getGoogleLoginUrl(uid),
        googleRegisterUrl: getGoogleRegisterUrl(uid),
      }));
      return;
    }

    next(err);
  }
});

web.post('/interaction/:uid/2fa', formParser, loginLimiter, async (req, res, next) => {
  try {
    if (!isTwoFactorEnabled()) {
      res.status(404).json({ error: '2FA is disabled' });
      return;
    }

    const { uid } = req.params;
    const { challenge = '', otp = '' } = req.body;

    const pending = consumeTotpChallenge(challenge, uid);
    if (!pending) {
      res.status(401).setHeader('Content-Type', 'text/html; charset=utf-8');
      res.end(renderLoginPage({ basePath, uid, twoFactorEnabled: isTwoFactorEnabled(), error: 'Session expired. Sign in again.' }));
      return;
    }

    const resolvedUser = findUserById(pending.accountId);

    if (!resolvedUser) {
      res.status(401).setHeader('Content-Type', 'text/html; charset=utf-8');
      res.end(renderLoginPage({ basePath, uid, twoFactorEnabled: isTwoFactorEnabled(), error: 'Unknown account. Sign in again.' }));
      return;
    }

    if (!verifyTotpToken(resolvedUser, otp)) {
      const retryChallenge = createTotpChallenge(uid, resolvedUser.id, pending.intent || 'login');
      res.status(401).setHeader('Content-Type', 'text/html; charset=utf-8');
      res.end(renderLoginPage({
        basePath,
        uid,
        twoFactorEnabled: isTwoFactorEnabled(),
        username: resolvedUser.username,
        otp,
        error: 'Invalid verification code',
        googleChallenge: retryChallenge,
        googleAccountLabel: resolvedUser.email || resolvedUser.username,
        qrSetupUrl: getInteractionQrSetupUrl(uid, resolvedUser.id),
      }));
      return;
    }

    if (pending.intent === 'register' && isPasskeyEnabled() && !hasPasskeys(resolvedUser)) {
      await renderPasskeyOnboardingForUser(req, res, uid, resolvedUser);
      return;
    }

    await finishLogin(req, res, resolvedUser.id);
  } catch (err) {
    if (isMissingInteractionSession(err)) {
      respondExpiredSession(res);
      return;
    }
    next(err);
  }
});

web.post('/interaction/:uid/confirm', formParser, async (req, res, next) => {
  try {
    const interactionDetails = await provider.interactionDetails(req, res);
    const { prompt: { details } } = interactionDetails;

    const grant = interactionDetails.grantId
      ? await provider.Grant.find(interactionDetails.grantId)
      : new provider.Grant({
          accountId: interactionDetails.session.accountId,
          clientId: interactionDetails.params.client_id,
        });

    if (details.missingOIDCScope) {
      grant.addOIDCScope(details.missingOIDCScope.join(' '));
    }
    if (details.missingOIDCClaims) {
      grant.addOIDCClaims(details.missingOIDCClaims);
    }
    if (details.missingResourceScopes) {
      for (const [indicator, scopes] of Object.entries(details.missingResourceScopes)) {
        grant.addResourceScope(indicator, scopes.join(' '));
      }
    }

    const grantId = await grant.save();
    const result = { consent: { grantId } };

    await finishInteraction(req, res, result, {
      mergeWithLastSubmission: true,
      callbackStage: 'consent_allow',
      callbackStatus: 'success',
    });
  } catch (err) {
    if (isMissingInteractionSession(err)) {
      respondExpiredSession(res);
      return;
    }
    next(err);
  }
});

web.post('/interaction/:uid/abort', formParser, async (req, res, next) => {
  try {
    const result = {
      error: 'access_denied',
      error_description: 'End-user denied consent',
    };

    await finishInteraction(req, res, result, {
      mergeWithLastSubmission: false,
      callbackStage: 'consent_deny',
      callbackStatus: 'denied',
    });
  } catch (err) {
    if (isMissingInteractionSession(err)) {
      respondExpiredSession(res);
      return;
    }
    next(err);
  }
});

function canAutoRegisterClientUri(req, rawUri) {
  try {
    let uri;
    try {
      uri = new URL(String(rawUri || ''));
    } catch {
      return false;
    }

    const uriOrigin = uri.origin;
    if (allowedOriginSet.has(uriOrigin)) return true;

    const requestOrigin = getRequestOrigin(req);
    if (requestOrigin && uriOrigin === requestOrigin) return true;

    const requestHost = String(req.get('x-forwarded-host') || req.get('host') || '').split(',')[0].trim().toLowerCase();
    const uriHost = String(uri.host || '').trim().toLowerCase();
    if (requestHost && uriHost && requestHost === uriHost) return true;

    const requestHostname = requestHost.includes(':') ? requestHost.split(':')[0] : requestHost;
    const uriHostname = String(uri.hostname || '').trim().toLowerCase();
    if (requestHostname && uriHostname && requestHostname === uriHostname) return true;

    const allowedHosts = new Set(
      [...allowedOriginSet]
        .map((origin) => hostFromUrl(origin).toLowerCase())
        .filter(Boolean),
    );
    if (allowedHosts.has(uriHost)) return true;

    return false;
  } catch {
    return false;
  }
}

web.use('/auth', (req, _res, next) => {
  const requestOrigin = getRequestOrigin(req);
  if (requestOrigin && requestOrigin !== issuerUrl.origin) {
    const canonicalAuthUrl = new URL(resolvePath(basePath, '/auth'), `${issuerUrl.origin}/`);
    const rawQuery = String(req.url || '').split('?')[1] || '';
    if (rawQuery) canonicalAuthUrl.search = rawQuery;
    _res.redirect(307, canonicalAuthUrl.toString());
    return;
  }

  const clientId = String(req.query.client_id || '').trim();
  const redirectUri = String(req.query.redirect_uri || '').trim();
  if (!clientId || !redirectUri || !canAutoRegisterClientUri(req, redirectUri)) {
    next();
    return;
  }
  try {
    ensureClientRedirectUri(clientId, redirectUri);
  } catch (error) {
    console.warn('Auto-register redirect_uri failed', {
      clientId,
      redirectUri,
      message: error?.message,
    });
  }
  next();
});

web.use('/session/end', (req, _res, next) => {
  const requestOrigin = getRequestOrigin(req);
  if (requestOrigin && requestOrigin !== issuerUrl.origin) {
    const canonicalSessionEndUrl = new URL(resolvePath(basePath, '/session/end'), `${issuerUrl.origin}/`);
    const rawQuery = String(req.url || '').split('?')[1] || '';
    if (rawQuery) canonicalSessionEndUrl.search = rawQuery;
    _res.redirect(307, canonicalSessionEndUrl.toString());
    return;
  }

  const clientId = String(req.query.client_id || '').trim();
  const postLogoutRedirectUri = String(req.query.post_logout_redirect_uri || '').trim();
  if (!clientId || !postLogoutRedirectUri || !canAutoRegisterClientUri(req, postLogoutRedirectUri)) {
    next();
    return;
  }
  try {
    ensureClientPostLogoutRedirectUri(clientId, postLogoutRedirectUri);
  } catch (error) {
    console.warn('Auto-register post_logout_redirect_uri failed', {
      clientId,
      postLogoutRedirectUri,
      message: error?.message,
    });
  }
  next();
});

web.use(provider.callback());

if (basePath) {
  app.use(basePath, web);
} else {
  app.use(web);
}

app.use((err, _req, res, _next) => {
  console.error(err);
  if (!res.headersSent) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.listen(port, () => {
  console.log(`OAuth2/OIDC server started at ${issuer}`);
  console.log('OpenID configuration:', `${issuer}/.well-known/openid-configuration`);
});
