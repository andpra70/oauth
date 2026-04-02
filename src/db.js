import { copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import argon2 from 'argon2';
import speakeasy from 'speakeasy';

const dbPath = 'data/oauth/db.json';
const dbSeedPath = 'bootstrap-data/oauth/db.json';

function normalizeBasePath(value) {
  const raw = String(value || '').trim();
  if (!raw || raw === '/') return '';
  return `/${raw.replace(/^\/+|\/+$/g, '')}`;
}

function parseUriList(value) {
  return String(value || '')
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);
}

function uniq(values) {
  return [...new Set(values)];
}

function normalizeOrigin(value) {
  try {
    return new URL(value).origin;
  } catch {
    return '';
  }
}

function buildDefaultClientUrls() {
  const issuer = process.env.ISSUER || 'http://localhost:9000';
  const issuerUrl = new URL(issuer);
  const basePath = normalizeBasePath(process.env.BASE_PATH || issuerUrl.pathname);
  const configuredOrigins = parseUriList(process.env.ALLOWED_ORIGINS)
    .map((value) => normalizeOrigin(value))
    .filter(Boolean);
  const origins = uniq([issuerUrl.origin, ...configuredOrigins]);
  const redirectUris = [];
  const postLogoutRedirectUris = [];

  for (const origin of origins) {
    const baseUrl = new URL(basePath ? `${basePath}/` : '/', `${origin}/`);
    redirectUris.push(new URL('app/callback', baseUrl).toString());
    redirectUris.push(new URL('authWidget/callback', baseUrl).toString());
    postLogoutRedirectUris.push(new URL('app', baseUrl).toString());
    postLogoutRedirectUris.push(new URL('authWidget', baseUrl).toString());
  }

  return {
    redirectUris: uniq(redirectUris).join(','),
    postLogoutRedirectUris: uniq(postLogoutRedirectUris).join(','),
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
    users: Array.isArray(parsed.users)
      ? parsed.users.map((user) => ({
          ...user,
          passkeys: Array.isArray(user?.passkeys) ? user.passkeys : [],
        }))
      : [],
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
    mkdirSync('data/oauth', { recursive: true });
    if (existsSync(dbSeedPath)) {
      copyFileSync(dbSeedPath, dbPath);
      return;
    }
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
  const configuredRedirectUris = process.env.DEFAULT_CLIENT_REDIRECT_URIS || process.env.DEFAULT_CLIENT_REDIRECT_URI || '';
  const configuredPostLogoutRedirectUris = process.env.DEFAULT_CLIENT_POST_LOGOUT_REDIRECT_URIS || process.env.DEFAULT_CLIENT_POST_LOGOUT_REDIRECT_URI || '';
  const redirectUris = uniq([
    ...parseUriList(configuredRedirectUris),
    ...parseUriList(defaultClientUrls.redirectUris),
  ]);
  const postLogoutRedirectUris = uniq([
    ...parseUriList(configuredPostLogoutRedirectUris),
    ...parseUriList(defaultClientUrls.postLogoutRedirectUris),
  ]);

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

export function ensureClientRedirectUri(clientId, redirectUri) {
  const id = String(clientId || '').trim();
  const uri = String(redirectUri || '').trim();
  if (!id || !uri) return false;

  let parsed;
  try {
    parsed = new URL(uri);
  } catch {
    return false;
  }

  const normalizedUri = parsed.toString();
  const state = loadState();
  const clientIndex = state.oauth_clients.findIndex((item) => item.client_id === id);
  if (clientIndex < 0) return false;

  const client = state.oauth_clients[clientIndex];
  const current = Array.isArray(client.redirect_uris) ? client.redirect_uris : [];
  if (current.includes(normalizedUri)) return false;

  client.redirect_uris = [...current, normalizedUri];
  state.oauth_clients[clientIndex] = client;
  saveState(state);
  return true;
}

export function ensureClientPostLogoutRedirectUri(clientId, postLogoutRedirectUri) {
  const id = String(clientId || '').trim();
  const uri = String(postLogoutRedirectUri || '').trim();
  if (!id || !uri) return false;

  let parsed;
  try {
    parsed = new URL(uri);
  } catch {
    return false;
  }

  const normalizedUri = parsed.toString();
  const state = loadState();
  const clientIndex = state.oauth_clients.findIndex((item) => item.client_id === id);
  if (clientIndex < 0) return false;

  const client = state.oauth_clients[clientIndex];
  const current = Array.isArray(client.post_logout_redirect_uris) ? client.post_logout_redirect_uris : [];
  if (current.includes(normalizedUri)) return false;

  client.post_logout_redirect_uris = [...current, normalizedUri];
  state.oauth_clients[clientIndex] = client;
  saveState(state);
  return true;
}

function normalizeUriList(value) {
  const entries = Array.isArray(value) ? value : String(value || '').split(/[\n,]/g);
  return uniq(entries.map((item) => String(item || '').trim()).filter(Boolean));
}

function normalizeStringList(value, {
  fallback = [],
} = {}) {
  const entries = Array.isArray(value) ? value : String(value || '').split(/[\n,]/g);
  const normalized = uniq(entries.map((item) => String(item || '').trim()).filter(Boolean));
  return normalized.length > 0 ? normalized : [...fallback];
}

export function updateClientRedirectUris(clientId, {
  redirectUris = [],
  postLogoutRedirectUris = [],
} = {}) {
  const id = String(clientId || '').trim();
  if (!id) {
    throw new Error('Client ID is required');
  }

  const normalizedRedirectUris = normalizeUriList(redirectUris).map((uri) => {
    try {
      return new URL(uri).toString();
    } catch {
      throw new Error(`Invalid redirect URI: ${uri}`);
    }
  });

  const normalizedPostLogoutRedirectUris = normalizeUriList(postLogoutRedirectUris).map((uri) => {
    try {
      return new URL(uri).toString();
    } catch {
      throw new Error(`Invalid post logout redirect URI: ${uri}`);
    }
  });

  if (normalizedRedirectUris.length === 0) {
    throw new Error('At least one redirect URI is required');
  }

  const state = loadState();
  const clientIndex = state.oauth_clients.findIndex((item) => item.client_id === id);
  if (clientIndex < 0) {
    throw new Error('Client not found');
  }

  const client = state.oauth_clients[clientIndex];
  client.redirect_uris = normalizedRedirectUris;
  client.post_logout_redirect_uris = normalizedPostLogoutRedirectUris;
  state.oauth_clients[clientIndex] = client;
  saveState(state);

  return {
    client_id: client.client_id,
    redirect_uris: client.redirect_uris,
    post_logout_redirect_uris: client.post_logout_redirect_uris,
  };
}

export function createClient(input = {}) {
  const clientId = String(input.client_id || '').trim();
  const tokenEndpointAuthMethod = String(input.token_endpoint_auth_method || 'none').trim() || 'none';
  const clientSecret = String(input.client_secret || '').trim();
  const scope = String(input.scope || 'openid profile email offline_access').trim() || 'openid profile email offline_access';

  if (!clientId) {
    throw new Error('Client ID is required');
  }

  const allowedAuthMethods = new Set(['none', 'client_secret_post', 'client_secret_basic']);
  if (!allowedAuthMethods.has(tokenEndpointAuthMethod)) {
    throw new Error('Unsupported token endpoint auth method');
  }

  if (tokenEndpointAuthMethod !== 'none' && clientSecret.length < 24) {
    throw new Error('Client secret must be at least 24 chars long');
  }

  const redirectUris = normalizeUriList(input.redirect_uris).map((uri) => {
    try {
      return new URL(uri).toString();
    } catch {
      throw new Error(`Invalid redirect URI: ${uri}`);
    }
  });
  const postLogoutRedirectUris = normalizeUriList(input.post_logout_redirect_uris).map((uri) => {
    try {
      return new URL(uri).toString();
    } catch {
      throw new Error(`Invalid post logout redirect URI: ${uri}`);
    }
  });

  if (redirectUris.length === 0) {
    throw new Error('At least one redirect URI is required');
  }

  const grantTypes = normalizeStringList(input.grant_types, {
    fallback: ['authorization_code', 'refresh_token'],
  });
  const responseTypes = normalizeStringList(input.response_types, {
    fallback: ['code'],
  });

  const state = loadState();
  const existing = state.oauth_clients.find((client) => client.client_id === clientId);
  if (existing) {
    throw new Error('Client already exists');
  }

  const client = {
    client_id: clientId,
    client_secret: tokenEndpointAuthMethod === 'none' ? '' : clientSecret,
    redirect_uris: redirectUris,
    post_logout_redirect_uris: postLogoutRedirectUris,
    grant_types: grantTypes,
    response_types: responseTypes,
    scope,
    token_endpoint_auth_method: tokenEndpointAuthMethod,
  };

  state.oauth_clients.push(client);
  saveState(state);
  return client;
}

export function deleteClient(clientId) {
  const id = String(clientId || '').trim();
  if (!id) {
    throw new Error('Client ID is required');
  }

  const state = loadState();
  const index = state.oauth_clients.findIndex((client) => client.client_id === id);
  if (index < 0) {
    throw new Error('Client not found');
  }

  const [removed] = state.oauth_clients.splice(index, 1);
  saveState(state);
  return removed;
}

function sanitizeClientRow(row) {
  if (!row || typeof row !== 'object') return null;
  const tokenEndpointAuthMethod = row.token_endpoint_auth_method || 'none';
  return {
    client_id: String(row.client_id || ''),
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
}

export function findClientById(clientId) {
  const id = String(clientId || '').trim();
  if (!id) return null;
  const state = loadState();
  const row = state.oauth_clients.find((client) => client.client_id === id);
  return sanitizeClientRow(row);
}

export function upsertClientMetadata(metadata = {}) {
  const client = sanitizeClientRow(metadata);
  if (!client?.client_id) {
    throw new Error('Client ID is required');
  }

  const state = loadState();
  const index = state.oauth_clients.findIndex((item) => item.client_id === client.client_id);
  if (index >= 0) {
    state.oauth_clients[index] = client;
  } else {
    state.oauth_clients.push(client);
  }
  saveState(state);
  return client;
}

export function findUserByUsername(username) {
  const state = loadState();
  return state.users.find((user) => user.username === username);
}

export function findUserById(id) {
  const state = loadState();
  return state.users.find((user) => user.id === id);
}

export function findUserByPasskeyCredentialId(credentialId) {
  const target = String(credentialId || '');
  if (!target) return null;
  const state = loadState();
  return state.users.find((user) => (user.passkeys || []).some((item) => item.id === target));
}

export function findPasskeyByCredentialId(credentialId) {
  const target = String(credentialId || '');
  if (!target) return null;
  const user = findUserByPasskeyCredentialId(target);
  if (!user) return null;
  const passkey = (user.passkeys || []).find((item) => item.id === target);
  if (!passkey) return null;
  return { user, passkey };
}

export function listUsers() {
  const state = loadState();
  return [...state.users].sort((left, right) => {
    const leftKey = String(left.username || left.email || left.id || '').toLowerCase();
    const rightKey = String(right.username || right.email || right.id || '').toLowerCase();
    return leftKey.localeCompare(rightKey);
  });
}

async function hashPassword(password) {
  return argon2.hash(password, {
    type: argon2.argon2id,
    memoryCost: 19456,
    timeCost: 2,
    parallelism: 1,
  });
}

function buildUserPayload(state, input, existing = null) {
  const username = String(input.username || '').trim();
  const email = normalizeEmail(input.email || '') || null;
  const authProvider = String(input.auth_provider || existing?.auth_provider || 'local').trim() || 'local';
  const picture = String(input.picture || '').trim() || null;
  const googleSubject = String(input.google_subject || '').trim() || null;
  const totpEnabled = String(input.totp_enabled || existing?.totp_enabled || '0') === '1' ? 1 : 0;

  if (!username) {
    throw new Error('Username is required');
  }

  const duplicate = state.users.find((user) => user.username === username && user.id !== existing?.id);
  if (duplicate) {
    throw new Error('Username already exists');
  }

  if (email) {
    const duplicateEmail = state.users.find((user) => normalizeEmail(user.email) === email && user.id !== existing?.id);
    if (duplicateEmail) {
      throw new Error('Email already exists');
    }
  }

  return {
    username,
    email,
    auth_provider: authProvider,
    picture,
    google_subject: googleSubject,
    totp_enabled: totpEnabled,
  };
}

export async function createUser(input) {
  const state = loadState();
  const payload = buildUserPayload(state, input);
  const password = String(input.password || '');
  const timestamp = nowIso();

  if (payload.auth_provider === 'local' && password.length < 12) {
    throw new Error('Password must be at least 12 chars long');
  }

  const secret = speakeasy.generateSecret({ name: `OAuth2 (${payload.username})` });
  const user = {
    id: newId('usr'),
    ...payload,
    totp_secret: secret.base32,
    passkeys: [],
    created_at: timestamp,
    updated_at: timestamp,
  };

  if (password) {
    user.password_hash = await hashPassword(password);
  }

  state.users.push(user);
  saveState(state);
  return user;
}

export async function updateUser(id, input) {
  const state = loadState();
  const index = state.users.findIndex((user) => user.id === id);
  if (index < 0) {
    throw new Error('User not found');
  }

  const existing = state.users[index];
  const payload = buildUserPayload(state, input, existing);
  const password = String(input.password || '');

  state.users[index] = {
    ...existing,
    ...payload,
    updated_at: nowIso(),
  };

  if (!state.users[index].totp_secret) {
    state.users[index].totp_secret = speakeasy.generateSecret({ name: `OAuth2 (${payload.username})` }).base32;
  }

  if (password) {
    if (password.length < 12) {
      throw new Error('Password must be at least 12 chars long');
    }
    state.users[index].password_hash = await hashPassword(password);
  }

  saveState(state);
  return state.users[index];
}

export function updateUserProfile(id, input) {
  const state = loadState();
  const index = state.users.findIndex((user) => user.id === id);
  if (index < 0) {
    throw new Error('User not found');
  }

  const payload = (input && typeof input === 'object') ? input : {};
  const allowedKeys = new Set(['preferred_username', 'email', 'picture']);
  const providedKeys = Object.keys(payload);
  const forbiddenKey = providedKeys.find((key) => !allowedKeys.has(key));
  if (forbiddenKey) {
    throw new Error(`Field "${forbiddenKey}" is not editable`);
  }

  const existing = state.users[index];
  const nextUsername = Object.hasOwn(payload, 'preferred_username')
    ? String(payload.preferred_username || '').trim()
    : existing.username;
  const nextEmail = Object.hasOwn(payload, 'email')
    ? (normalizeEmail(payload.email || '') || null)
    : (existing.email || null);
  const nextPicture = Object.hasOwn(payload, 'picture')
    ? (String(payload.picture || '').trim() || null)
    : (existing.picture || null);

  if (!nextUsername) {
    throw new Error('preferred_username is required');
  }

  const duplicateUsername = state.users.find((user) => user.id !== existing.id && user.username === nextUsername);
  if (duplicateUsername) {
    throw new Error('Username already exists');
  }

  if (nextEmail) {
    const duplicateEmail = state.users.find((user) => user.id !== existing.id && normalizeEmail(user.email) === nextEmail);
    if (duplicateEmail) {
      throw new Error('Email already exists');
    }
  }

  state.users[index] = {
    ...existing,
    username: nextUsername,
    email: nextEmail,
    picture: nextPicture,
    updated_at: nowIso(),
  };

  saveState(state);
  return state.users[index];
}

export function deleteUser(id) {
  const state = loadState();
  const index = state.users.findIndex((user) => user.id === id);
  if (index < 0) {
    throw new Error('User not found');
  }

  const [removed] = state.users.splice(index, 1);
  saveState(state);
  return removed;
}

export function findUserByGoogleSubject(googleSubject) {
  const state = loadState();
  return state.users.find((user) => user.google_subject === googleSubject);
}

export function upsertGoogleUser(profile) {
  const state = loadState();
  const googleSubject = String(profile.sub || '').trim();
  const email = normalizeEmail(profile.email);
  const picture = String(profile.picture || '').trim() || null;
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
    existing.picture = picture || existing.picture || null;
    if (!existing.username) {
      existing.username = buildUniqueUsername(state, profile.email || profile.name || 'google-user');
    }
    if (!existing.totp_secret && secret?.base32) {
      existing.totp_secret = secret.base32;
    }
    existing.totp_enabled = 1;
    existing.updated_at = timestamp;
    if (!Array.isArray(existing.passkeys)) {
      existing.passkeys = [];
    }
    saveState(state);
    return existing;
  }

  const secret = speakeasy.generateSecret({ name: `OAuth2 (${profile.email || profile.name || 'google-user'})` });
  const user = {
    id: newId('usr'),
    username: buildUniqueUsername(state, profile.email || profile.name || 'google-user'),
    email: email || null,
    picture,
    auth_provider: 'google',
    google_subject: googleSubject,
    totp_secret: secret.base32,
    totp_enabled: 1,
    passkeys: [],
    created_at: timestamp,
    updated_at: timestamp,
  };

  state.users.push(user);
  saveState(state);
  return user;
}

export function getClients() {
  const state = loadState();
  return state.oauth_clients
    .map((row) => sanitizeClientRow(row))
    .filter(Boolean);
}

export function upsertUserPasskey(userId, input) {
  const state = loadState();
  const index = state.users.findIndex((user) => user.id === userId);
  if (index < 0) {
    throw new Error('User not found');
  }

  const credentialId = String(input?.id || '').trim();
  if (!credentialId) {
    throw new Error('Passkey credential id is required');
  }

  const entry = {
    id: credentialId,
    public_key: String(input?.public_key || ''),
    counter: Number(input?.counter || 0),
    transports: Array.isArray(input?.transports) ? input.transports : [],
    device_type: String(input?.device_type || ''),
    backed_up: Boolean(input?.backed_up),
    created_at: String(input?.created_at || nowIso()),
    updated_at: nowIso(),
    last_used_at: input?.last_used_at ? String(input.last_used_at) : null,
  };

  if (!Array.isArray(state.users[index].passkeys)) {
    state.users[index].passkeys = [];
  }

  const existingIndex = state.users[index].passkeys.findIndex((item) => item.id === credentialId);
  if (existingIndex >= 0) {
    state.users[index].passkeys[existingIndex] = {
      ...state.users[index].passkeys[existingIndex],
      ...entry,
      created_at: state.users[index].passkeys[existingIndex].created_at || entry.created_at,
    };
  } else {
    state.users[index].passkeys.push(entry);
  }

  state.users[index].updated_at = nowIso();
  saveState(state);
  return state.users[index];
}

export function touchUserPasskeyCounter(userId, credentialId, counter) {
  const state = loadState();
  const userIndex = state.users.findIndex((item) => item.id === userId);
  if (userIndex < 0) {
    throw new Error('User not found');
  }
  const passkeys = Array.isArray(state.users[userIndex].passkeys) ? state.users[userIndex].passkeys : [];
  const passkeyIndex = passkeys.findIndex((item) => item.id === credentialId);
  if (passkeyIndex < 0) {
    throw new Error('Passkey not found');
  }

  passkeys[passkeyIndex].counter = Number(counter || 0);
  passkeys[passkeyIndex].last_used_at = nowIso();
  passkeys[passkeyIndex].updated_at = nowIso();
  state.users[userIndex].passkeys = passkeys;
  state.users[userIndex].updated_at = nowIso();
  saveState(state);
  return state.users[userIndex];
}

export function clearUserPasskeys(userId) {
  const state = loadState();
  const userIndex = state.users.findIndex((item) => item.id === userId);
  if (userIndex < 0) {
    throw new Error('User not found');
  }
  state.users[userIndex].passkeys = [];
  state.users[userIndex].updated_at = nowIso();
  saveState(state);
  return state.users[userIndex];
}
