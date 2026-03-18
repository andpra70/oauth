import Database from 'better-sqlite3';
import argon2 from 'argon2';
import speakeasy from 'speakeasy';

const db = new Database('data/oauth/oauth.db');

db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

export function ensureSchema() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT NOT NULL UNIQUE,
      email TEXT,
      password_hash TEXT NOT NULL,
      totp_secret TEXT NOT NULL,
      totp_enabled INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS oauth_clients (
      client_id TEXT PRIMARY KEY,
      client_secret TEXT NOT NULL,
      redirect_uris TEXT NOT NULL,
      post_logout_redirect_uris TEXT NOT NULL,
      grant_types TEXT NOT NULL,
      response_types TEXT NOT NULL,
      scope TEXT NOT NULL,
      token_endpoint_auth_method TEXT NOT NULL
    );
  `);
}

function nowIso() {
  return new Date().toISOString();
}

function newId(prefix) {
  return `${prefix}_${Math.random().toString(36).slice(2, 12)}${Date.now().toString(36)}`;
}

export async function seedAdminFromEnv() {
  const username = process.env.ADMIN_USERNAME || 'admin';
  const password = process.env.ADMIN_PASSWORD || '';
  const email = process.env.ADMIN_EMAIL || null;

  if (!password || password.length < 12) {
    throw new Error('ADMIN_PASSWORD must be set and at least 12 chars long');
  }

  const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
  if (existing) return;

  const secret = speakeasy.generateSecret({ name: `OAuth2 (${username})` });
  const passwordHash = await argon2.hash(password, {
    type: argon2.argon2id,
    memoryCost: 19456,
    timeCost: 2,
    parallelism: 1,
  });

  db.prepare(
    `INSERT INTO users (id, username, email, password_hash, totp_secret, totp_enabled, created_at)
     VALUES (?, ?, ?, ?, ?, 1, ?)`
  ).run(newId('usr'), username, email, passwordHash, secret.base32, nowIso());

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
  const redirectUri = process.env.DEFAULT_CLIENT_REDIRECT_URI || 'http://localhost:8080/callback';
  const postLogoutRedirectUri = process.env.DEFAULT_CLIENT_POST_LOGOUT_REDIRECT_URI || 'http://localhost:8080';

  if (authMethod !== 'none' && (!clientSecret || clientSecret.length < 24)) {
    throw new Error('DEFAULT_CLIENT_SECRET must be set and at least 24 chars long');
  }

  db.prepare(
    `INSERT INTO oauth_clients
      (client_id, client_secret, redirect_uris, post_logout_redirect_uris, grant_types, response_types, scope, token_endpoint_auth_method)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    + ` ON CONFLICT(client_id) DO UPDATE SET`
    + ` client_secret = excluded.client_secret,`
    + ` redirect_uris = excluded.redirect_uris,`
    + ` post_logout_redirect_uris = excluded.post_logout_redirect_uris,`
    + ` grant_types = excluded.grant_types,`
    + ` response_types = excluded.response_types,`
    + ` scope = excluded.scope,`
    + ` token_endpoint_auth_method = excluded.token_endpoint_auth_method`
  ).run(
    clientId,
    authMethod === 'none' ? '' : clientSecret,
    JSON.stringify([redirectUri]),
    JSON.stringify([postLogoutRedirectUri]),
    JSON.stringify(['authorization_code', 'refresh_token']),
    JSON.stringify(['code']),
    'openid profile email offline_access',
    authMethod
  );
}

export function findUserByUsername(username) {
  return db.prepare('SELECT * FROM users WHERE username = ?').get(username);
}

export function findUserById(id) {
  return db.prepare('SELECT * FROM users WHERE id = ?').get(id);
}

export function getClients() {
  const rows = db.prepare('SELECT * FROM oauth_clients').all();
  return rows.map((row) => {
    const tokenEndpointAuthMethod = row.token_endpoint_auth_method || 'none';

    return {
      client_id: row.client_id,
      ...(tokenEndpointAuthMethod !== 'none' && row.client_secret
        ? { client_secret: row.client_secret }
        : {}),
      redirect_uris: JSON.parse(row.redirect_uris),
      post_logout_redirect_uris: JSON.parse(row.post_logout_redirect_uris),
      grant_types: JSON.parse(row.grant_types),
      response_types: JSON.parse(row.response_types),
      scope: row.scope,
      token_endpoint_auth_method: tokenEndpointAuthMethod,
    };
  });
}
