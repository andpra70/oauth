import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import argon2 from 'argon2';
import speakeasy from 'speakeasy';

const dbPath = 'data/oauth/db.json';

function normalizeBasePath(value) {
  const raw = String(value || '').trim();
  if (!raw || raw === '/') return '';
  return `/${raw.replace(/^\/+|\/+$/g, '')}`;
}

function buildDefaultClientUrls() {
  const issuer = process.env.ISSUER || 'http://localhost:9000';
  const issuerUrl = new URL(issuer);
  const basePath = normalizeBasePath(process.env.BASE_PATH || issuerUrl.pathname);
  const baseUrl = new URL(basePath ? `${basePath}/` : '/', issuerUrl.origin);
  const callbackApp = new URL('app/callback', baseUrl).toString();
  const callbackExample = new URL('example/callback', baseUrl).toString();
  const postLogoutApp = new URL('app', baseUrl).toString();
  const postLogoutExample = new URL('example', baseUrl).toString();

  return {
    redirectUris: `${callbackApp},${callbackExample}`,
    postLogoutRedirectUris: `${postLogoutApp},${postLogoutExample}`,
  };
}

function defaultState() {
  return {
    users: [],
    oauth_clients: [],
  };
}

function loadState() {
  if (!existsSync(dbPath)) {
    return defaultState();
  }

  const raw = readFileSync(dbPath, 'utf8').trim();
  if (!raw) {
    return defaultState();
  }

  const parsed = JSON.parse(raw);
  return {
    users: Array.isArray(parsed.users) ? parsed.users : [],
    oauth_clients: Array.isArray(parsed.oauth_clients) ? parsed.oauth_clients : [],
  };
}

function saveState(state) {
  writeFileSync(dbPath, `${JSON.stringify(state, null, 2)}\n`);
}

function nowIso() {
  return new Date().toISOString();
}

function newId(prefix) {
  return `${prefix}_${Math.random().toString(36).slice(2, 12)}${Date.now().toString(36)}`;
}

function normalizeEmail(email) {
  return String(email || '').trim().toLowerCase();
}

function normalizeUsername(value) {
  return String(value || '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 32);
}

function buildUniqueUsername(state, preferred) {
  const base = normalizeUsername(preferred) || 'google-user';

  let candidate = base;
  let counter = 1;
  while (state.users.some((user) => user.username === candidate)) {
    counter += 1;
    candidate = `${base.slice(0, Math.max(1, 28 - String(counter).length))}-${counter}`;
  }

  return candidate;
}

export function ensureSchema() {
  if (!existsSync(dbPath)) {
    saveState(defaultState());
    return;
  }

  const state = loadState();
  saveState(state);
}

export async function seedAdminFromEnv() {
  const username = process.env.ADMIN_USERNAME || 'admin';
  const password = process.env.ADMIN_PASSWORD || '';
  const email = process.env.ADMIN_EMAIL || null;

  if (!password || password.length < 12) {
    throw new Error('ADMIN_PASSWORD must be set and at least 12 chars long');
  }

  const state = loadState();
  const existing = state.users.find((user) => user.username === username);
  if (existing) return;

  const secret = speakeasy.generateSecret({ name: `OAuth2 (${username})` });
  const passwordHash = await argon2.hash(password, {
    type: argon2.argon2id,
    memoryCost: 19456,
    timeCost: 2,
    parallelism: 1,
  });

  state.users.push({
    id: newId('usr'),
    username,
    email,
    password_hash: passwordHash,
    totp_secret: secret.base32,
    totp_enabled: 1,
    created_at: nowIso(),
  });
  saveState(state);

  console.log('Admin user created. Configure your Authenticator app with this secret:');
  console.log(secret.base32);
  if (secret.otpauth_url) {
    console.log('otpauth URL:', secret.otpauth_url);
  }
}

export function seedClientFromEnv() {
  const clientId = process.env.DEFAULT_CLIENT_ID || 'fileserver-web';
  const authMethod = process.env.DEFAULT_CLIENT_AUTH_METHOD || 'none';
  const clientSecret = process.env.DEFAULT_CLIENT_SECRET || '';
  const defaultClientUrls = buildDefaultClientUrls();
  const redirectUris = (process.env.DEFAULT_CLIENT_REDIRECT_URIS || process.env.DEFAULT_CLIENT_REDIRECT_URI || defaultClientUrls.redirectUris)
    .split(',')
    .map((value) => value.trim())
    .filter(Boolean);
  const postLogoutRedirectUris = (process.env.DEFAULT_CLIENT_POST_LOGOUT_REDIRECT_URIS || process.env.DEFAULT_CLIENT_POST_LOGOUT_REDIRECT_URI || defaultClientUrls.postLogoutRedirectUris)
    .split(',')
    .map((value) => value.trim())
    .filter(Boolean);

  if (authMethod !== 'none' && (!clientSecret || clientSecret.length < 24)) {
    throw new Error('DEFAULT_CLIENT_SECRET must be set and at least 24 chars long');
  }

  const state = loadState();
  const client = {
    client_id: clientId,
    client_secret: authMethod === 'none' ? '' : clientSecret,
    redirect_uris: redirectUris,
    post_logout_redirect_uris: postLogoutRedirectUris,
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
    scope: 'openid profile email offline_access',
    token_endpoint_auth_method: authMethod,
  };

  const existingIndex = state.oauth_clients.findIndex((item) => item.client_id === clientId);
  if (existingIndex >= 0) {
    state.oauth_clients[existingIndex] = client;
  } else {
    state.oauth_clients.push(client);
  }

  saveState(state);
}

export function findUserByUsername(username) {
  const state = loadState();
  return state.users.find((user) => user.username === username);
}

export function findUserById(id) {
  const state = loadState();
  return state.users.find((user) => user.id === id);
}

export function findUserByGoogleSubject(googleSubject) {
  const state = loadState();
  return state.users.find((user) => user.google_subject === googleSubject);
}

export function upsertGoogleUser(profile) {
  const state = loadState();
  const googleSubject = String(profile.sub || '').trim();
  const email = normalizeEmail(profile.email);
  if (!googleSubject) {
    throw new Error('Google subject is required');
  }

  const existing = state.users.find((user) => user.google_subject === googleSubject);
  const timestamp = nowIso();

  if (existing) {
    const secret = existing.totp_secret
      ? null
      : speakeasy.generateSecret({ name: `OAuth2 (${existing.username || profile.email || 'google-user'})` });
    existing.google_subject = googleSubject;
    existing.auth_provider = 'google';
    existing.email = email || existing.email || null;
    if (!existing.username) {
      existing.username = buildUniqueUsername(state, profile.email || profile.name || 'google-user');
    }
    if (!existing.totp_secret && secret?.base32) {
      existing.totp_secret = secret.base32;
    }
    existing.totp_enabled = 1;
    existing.updated_at = timestamp;
    saveState(state);
    return existing;
  }

  const secret = speakeasy.generateSecret({ name: `OAuth2 (${profile.email || profile.name || 'google-user'})` });
  const user = {
    id: newId('usr'),
    username: buildUniqueUsername(state, profile.email || profile.name || 'google-user'),
    email: email || null,
    auth_provider: 'google',
    google_subject: googleSubject,
    totp_secret: secret.base32,
    totp_enabled: 1,
    created_at: timestamp,
    updated_at: timestamp,
  };

  state.users.push(user);
  saveState(state);
  return user;
}

export function getClients() {
  const state = loadState();
  return state.oauth_clients.map((row) => {
    const tokenEndpointAuthMethod = row.token_endpoint_auth_method || 'none';

    return {
      client_id: row.client_id,
      ...(tokenEndpointAuthMethod !== 'none' && row.client_secret
        ? { client_secret: row.client_secret }
        : {}),
      redirect_uris: Array.isArray(row.redirect_uris) ? row.redirect_uris : [],
      post_logout_redirect_uris: Array.isArray(row.post_logout_redirect_uris) ? row.post_logout_redirect_uris : [],
      grant_types: Array.isArray(row.grant_types) ? row.grant_types : [],
      response_types: Array.isArray(row.response_types) ? row.response_types : [],
      scope: row.scope,
      token_endpoint_auth_method: tokenEndpointAuthMethod,
    };
  });
}
