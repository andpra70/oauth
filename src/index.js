import 'dotenv/config';
import { mkdirSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import argon2 from 'argon2';
import speakeasy from 'speakeasy';
import QRCode from 'qrcode';
import { Provider } from 'oidc-provider';
import { ensureSchema, findUserById, findUserByUsername, getClients, seedAdminFromEnv, seedClientFromEnv } from './db.js';
import { findAccount } from './account.js';
import { renderConsent, renderExpiredSession, renderLogin, renderTotp } from './html.js';
import { ensureOidcStore, JsonAdapter } from './oidc-adapter.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const publicDir = join(__dirname, '..', 'public');
const app = express();
const port = Number(process.env.PORT || 9000);
const issuer = process.env.ISSUER || `http://localhost:${port}`;
const cookieKeys = (process.env.COOKIE_KEYS || '').split(',').map((s) => s.trim()).filter(Boolean);
const trustProxy = String(process.env.TRUST_PROXY || 'false').toLowerCase() === 'true';
const allowedOrigins = (process.env.ALLOWED_ORIGINS || 'http://localhost:9000,http://localhost:8080,http://localhost')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);

function normalizeOrigin(value) {
  try {
    return new URL(value).origin;
  } catch {
    return '';
  }
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

function getQrSetupUrl() {
  const setupToken = process.env.SETUP_TOKEN || '';
  const adminUser = process.env.ADMIN_USERNAME || 'admin';
  if (!setupToken) return '';
  return `/setup/2fa-qr/${encodeURIComponent(adminUser)}?token=${encodeURIComponent(setupToken)}`;
}

async function getQrSetupPayload(username) {
  const user = findUserByUsername(username);
  if (!user?.totp_secret) {
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

function createTotpChallenge(uid, accountId) {
  const challenge = randomUUID();
  totpChallenges.set(challenge, {
    uid,
    accountId,
    expiresAt: Date.now() + 3 * 60 * 1000,
  });
  return challenge;
}

function consumeTotpChallenge(challenge, uid) {
  const data = totpChallenges.get(challenge);
  totpChallenges.delete(challenge);
  if (!data) return null;
  if (data.uid !== uid) return null;
  if (Date.now() > data.expiresAt) return null;
  return data;
}

function isMissingInteractionSession(error) {
  return error?.error === 'invalid_request' && error?.error_description === 'interaction session not found';
}

function respondExpiredSession(res) {
  res.status(401).setHeader('Content-Type', 'text/html; charset=utf-8');
  res.end(renderExpiredSession());
}

setInterval(() => {
  const now = Date.now();
  for (const [key, value] of totpChallenges.entries()) {
    if (value.expiresAt < now) totpChallenges.delete(key);
  }
}, 30_000).unref();

const provider = new Provider(issuer, {
  clients: getClients(),
  pkce: {
    methods: ['S256'],
    required: () => true,
  },
  scopes: ['openid', 'profile', 'email', 'offline_access'],
  claims: {
    openid: ['sub'],
    profile: ['preferred_username'],
    email: ['email'],
  },
  features: {
    devInteractions: { enabled: false },
    introspection: { enabled: true },
    revocation: { enabled: true },
    rpInitiatedLogout: { enabled: true },
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
      return `/interaction/${interaction.uid}`;
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
app.use(helmet({
  contentSecurityPolicy: {
    useDefaults: true,
    directives: {
      'script-src': ["'self'", "'unsafe-inline'"],
      'style-src': ["'self'", "'unsafe-inline'"],
      'form-action': ['*'],
    },
  },
}));

const formParser = express.urlencoded({ extended: false });

app.get('/health', (_req, res) => {
  res.json({ ok: true, issuer });
});

app.use('/app/assets', express.static(join(publicDir, 'assets')));

app.get(['/', '/app', '/app/callback'], (_req, res) => {
  res.sendFile(join(publicDir, 'index.html'));
});

app.get(['/example', '/example/callback'], (_req, res) => {
  res.sendFile(join(publicDir, 'example.html'));
});

app.get('/setup/2fa-qr/:username', async (req, res) => {
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
  res.end(`<img alt="qr" src="${payload.dataUrl}" /><p>${payload.otpauthUrl}</p>`);
});

app.get('/setup/2fa-qr/:username.json', async (req, res) => {
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

app.get('/interaction/:uid', async (req, res, next) => {
  try {
    const details = await provider.interactionDetails(req, res);
    const { uid, prompt, params } = details;

    if (prompt.name === 'login') {
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.end(renderLogin({ uid }));
      return;
    }

    if (prompt.name === 'consent') {
      const client = await provider.Client.find(params.client_id);
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.end(renderConsent({ uid, clientName: client?.clientName || params.client_id, scope: params.scope }));
      return;
    }

    res.status(400).send('Unsupported interaction');
  } catch (err) {
    next(err);
  }
});

app.post('/interaction/:uid/login', formParser, loginLimiter, async (req, res, next) => {
  try {
    const { uid } = req.params;
    const { username = '', password = '' } = req.body;

    const user = findUserByUsername(username.trim());
    if (!user) {
      res.status(401).setHeader('Content-Type', 'text/html; charset=utf-8');
      res.end(renderLogin({ uid, username, error: 'Invalid credentials' }));
      return;
    }

    const passwordOk = await argon2.verify(user.password_hash, password, {
      type: argon2.argon2id,
    });
    if (!passwordOk) {
      res.status(401).setHeader('Content-Type', 'text/html; charset=utf-8');
      res.end(renderLogin({ uid, username, error: 'Invalid credentials' }));
      return;
    }

    if (user.totp_enabled) {
      const challenge = createTotpChallenge(uid, user.id);
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.end(renderTotp({ uid, challenge, qrSetupUrl: getQrSetupUrl() }));
      return;
    }

    const result = {
      login: {
        accountId: user.id,
        remember: false,
      },
    };

    await provider.interactionFinished(req, res, result, { mergeWithLastSubmission: false });
  } catch (err) {
    if (isMissingInteractionSession(err)) {
      respondExpiredSession(res);
      return;
    }
    next(err);
  }
});

app.post('/interaction/:uid/2fa', formParser, loginLimiter, async (req, res, next) => {
  try {
    const { uid } = req.params;
    const { challenge = '', otp = '' } = req.body;

    const pending = consumeTotpChallenge(challenge, uid);
    if (!pending) {
      res.status(401).setHeader('Content-Type', 'text/html; charset=utf-8');
      res.end(renderLogin({ uid, error: 'Session expired. Sign in again.' }));
      return;
    }

    const resolvedUser = findUserById(pending.accountId);

    if (!resolvedUser) {
      res.status(401).setHeader('Content-Type', 'text/html; charset=utf-8');
      res.end(renderLogin({ uid, error: 'Unknown account. Sign in again.' }));
      return;
    }

    const valid = speakeasy.totp.verify({
      secret: resolvedUser.totp_secret,
      encoding: 'base32',
      token: String(otp).replace(/\s+/g, ''),
      window: 1,
    });

    if (!valid) {
      const retryChallenge = createTotpChallenge(uid, resolvedUser.id);
      res.status(401).setHeader('Content-Type', 'text/html; charset=utf-8');
      res.end(renderTotp({ uid, challenge: retryChallenge, error: 'Invalid verification code', qrSetupUrl: getQrSetupUrl() }));
      return;
    }

    const result = {
      login: {
        accountId: resolvedUser.id,
        remember: false,
      },
    };

    await provider.interactionFinished(req, res, result, { mergeWithLastSubmission: false });
  } catch (err) {
    if (isMissingInteractionSession(err)) {
      respondExpiredSession(res);
      return;
    }
    next(err);
  }
});

app.post('/interaction/:uid/confirm', formParser, async (req, res, next) => {
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

    await provider.interactionFinished(req, res, result, { mergeWithLastSubmission: true });
  } catch (err) {
    if (isMissingInteractionSession(err)) {
      respondExpiredSession(res);
      return;
    }
    next(err);
  }
});

app.post('/interaction/:uid/abort', formParser, async (req, res, next) => {
  try {
    const result = {
      error: 'access_denied',
      error_description: 'End-user denied consent',
    };

    await provider.interactionFinished(req, res, result, { mergeWithLastSubmission: false });
  } catch (err) {
    if (isMissingInteractionSession(err)) {
      respondExpiredSession(res);
      return;
    }
    next(err);
  }
});

app.use(provider.callback());

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
