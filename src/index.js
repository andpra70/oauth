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
import { ensureSchema, findUserById, findUserByUsername, getClients, seedAdminFromEnv, seedClientFromEnv, upsertGoogleUser } from './db.js';
import { findAccount } from './account.js';
import { renderConsent, renderExpiredSession, renderLogin } from './html.js';
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
const totpSetupSessions = new Map();
const googleLoginStates = new Map();

const googleClientId = process.env.GOOGLE_CLIENT_ID || '';
const googleClientSecret = process.env.GOOGLE_CLIENT_SECRET || '';
const googleCallbackPath = process.env.GOOGLE_CALLBACK_PATH || '/auth/google/callback';
const googleCallbackUrl = process.env.GOOGLE_CALLBACK_URL || new URL(googleCallbackPath, issuer).toString();
const googleEnabled = Boolean(googleClientId && googleClientSecret);

function getQrSetupUrl() {
  const setupToken = process.env.SETUP_TOKEN || '';
  const adminUser = process.env.ADMIN_USERNAME || 'admin';
  if (!setupToken) return '';
  return `/setup/2fa-qr/${encodeURIComponent(adminUser)}?token=${encodeURIComponent(setupToken)}`;
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

function createTotpChallenge(uid, accountId) {
  const challenge = randomUUID();
  totpChallenges.set(challenge, {
    uid,
    accountId,
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
  return `/interaction/${encodeURIComponent(uid)}/2fa-qr?token=${encodeURIComponent(token)}`;
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
  return `/interaction/${encodeURIComponent(uid)}/login/google`;
}

function getGoogleRegisterUrl(uid) {
  return `/interaction/${encodeURIComponent(uid)}/register/google`;
}

function createGoogleState(uid) {
  const state = randomUUID();
  googleLoginStates.set(state, {
    uid,
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

async function exchangeGoogleCode(code) {
  const response = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({
      code,
      client_id: googleClientId,
      client_secret: googleClientSecret,
      redirect_uri: googleCallbackUrl,
      grant_type: 'authorization_code',
    }),
  });

  if (!response.ok) {
    throw new Error(`Google token exchange failed with status ${response.status}`);
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
    throw new Error(`Google userinfo failed with status ${response.status}`);
  }

  return response.json();
}

async function startGoogleAuth(req, res, next) {
  try {
    if (!googleEnabled) {
      res.status(404).send('Google login is not configured');
      return;
    }

    const { uid } = req.params;
    await provider.interactionDetails(req, res);

    const state = createGoogleState(uid);
    const redirectUrl = new URL('https://accounts.google.com/o/oauth2/v2/auth');
    redirectUrl.searchParams.set('client_id', googleClientId);
    redirectUrl.searchParams.set('redirect_uri', googleCallbackUrl);
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
  for (const [key, value] of totpSetupSessions.entries()) {
    if (value.expiresAt < now) totpSetupSessions.delete(key);
  }
  for (const [key, value] of googleLoginStates.entries()) {
    if (value.expiresAt < now) googleLoginStates.delete(key);
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

app.get('/interaction/:uid/2fa-qr', async (req, res) => {
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
  res.end(`<img alt="qr" src="${payload.dataUrl}" /><p>${payload.otpauthUrl}</p>`);
});

app.get('/interaction/:uid', async (req, res, next) => {
  try {
    const details = await provider.interactionDetails(req, res);
    const { uid, prompt, params } = details;

    if (prompt.name === 'login') {
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.end(renderLogin({ uid, googleLoginUrl: getGoogleLoginUrl(uid), googleRegisterUrl: getGoogleRegisterUrl(uid) }));
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
    const { username = '', password = '', otp = '', challenge = '' } = req.body;

    if (challenge) {
      const pending = consumeTotpChallenge(challenge, uid);
      if (!pending) {
        res.status(401).setHeader('Content-Type', 'text/html; charset=utf-8');
        res.end(renderLogin({
          uid,
          error: 'Session expired. Sign in again.',
          googleLoginUrl: getGoogleLoginUrl(uid),
          googleRegisterUrl: getGoogleRegisterUrl(uid),
        }));
        return;
      }

      const resolvedUser = findUserById(pending.accountId);
      if (!resolvedUser) {
        res.status(401).setHeader('Content-Type', 'text/html; charset=utf-8');
        res.end(renderLogin({
          uid,
          error: 'Unknown account. Sign in again.',
          googleLoginUrl: getGoogleLoginUrl(uid),
          googleRegisterUrl: getGoogleRegisterUrl(uid),
        }));
        return;
      }

      if (!verifyTotpToken(resolvedUser, otp)) {
        const retryChallenge = createTotpChallenge(uid, resolvedUser.id);
        res.status(401).setHeader('Content-Type', 'text/html; charset=utf-8');
        res.end(renderLogin({
          uid,
          username: resolvedUser.username,
          otp,
          error: 'Invalid verification code',
          googleChallenge: retryChallenge,
          googleAccountLabel: resolvedUser.email || resolvedUser.username,
          qrSetupUrl: getInteractionQrSetupUrl(uid, resolvedUser.id),
        }));
        return;
      }

      const result = {
        login: {
          accountId: resolvedUser.id,
          remember: false,
        },
      };

      await provider.interactionFinished(req, res, result, { mergeWithLastSubmission: false });
      return;
    }

    const user = findUserByUsername(username.trim());
    if (!user || !user.password_hash) {
      res.status(401).setHeader('Content-Type', 'text/html; charset=utf-8');
      res.end(renderLogin({
        uid,
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
      res.end(renderLogin({
        uid,
        username,
        error: 'Invalid credentials',
        googleLoginUrl: getGoogleLoginUrl(uid),
        googleRegisterUrl: getGoogleRegisterUrl(uid),
      }));
      return;
    }

    if (user.totp_enabled) {
      if (!verifyTotpToken(user, otp)) {
        res.status(401).setHeader('Content-Type', 'text/html; charset=utf-8');
        res.end(renderLogin({
          uid,
          username,
          error: otp ? 'Invalid verification code' : 'Authenticator code is required',
          qrSetupUrl: getInteractionQrSetupUrl(uid, user.id),
          googleLoginUrl: getGoogleLoginUrl(uid),
          googleRegisterUrl: getGoogleRegisterUrl(uid),
        }));
        return;
      }
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

app.get('/interaction/:uid/login/google', startGoogleAuth);
app.get('/interaction/:uid/register/google', startGoogleAuth);

app.get(googleCallbackPath, async (req, res, next) => {
  const state = String(req.query.state || '');
  const code = String(req.query.code || '');
  const error = String(req.query.error || '');
  const pending = consumeGoogleState(state);
  const uid = pending?.uid || '';

  try {
    if (!googleEnabled) {
      res.status(404).send('Google login is not configured');
      return;
    }

    if (!pending || !uid) {
      res.status(400).send('Invalid Google login state');
      return;
    }

    if (error) {
      res.status(401).setHeader('Content-Type', 'text/html; charset=utf-8');
      res.end(renderLogin({
        uid,
        error: 'Google login was cancelled',
        googleLoginUrl: getGoogleLoginUrl(uid),
        googleRegisterUrl: getGoogleRegisterUrl(uid),
      }));
      return;
    }

    if (!code) {
      res.status(400).setHeader('Content-Type', 'text/html; charset=utf-8');
      res.end(renderLogin({
        uid,
        error: 'Missing Google authorization code',
        googleLoginUrl: getGoogleLoginUrl(uid),
        googleRegisterUrl: getGoogleRegisterUrl(uid),
      }));
      return;
    }

    const tokenSet = await exchangeGoogleCode(code);
    const profile = await fetchGoogleProfile(tokenSet.access_token);
    const user = upsertGoogleUser(profile);

    const challenge = createTotpChallenge(uid, user.id);
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.end(renderLogin({
      uid,
      username: user.username,
      googleChallenge: challenge,
      googleAccountLabel: user.email || user.username,
      qrSetupUrl: getInteractionQrSetupUrl(uid, user.id),
    }));
  } catch (err) {
    if (uid) {
      if (isMissingInteractionSession(err)) {
        respondExpiredSession(res);
        return;
      }

      res.status(401).setHeader('Content-Type', 'text/html; charset=utf-8');
      res.end(renderLogin({
        uid,
        error: 'Google login failed',
        googleLoginUrl: getGoogleLoginUrl(uid),
        googleRegisterUrl: getGoogleRegisterUrl(uid),
      }));
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

    if (!verifyTotpToken(resolvedUser, otp)) {
      const retryChallenge = createTotpChallenge(uid, resolvedUser.id);
      res.status(401).setHeader('Content-Type', 'text/html; charset=utf-8');
      res.end(renderLogin({
        uid,
        username: resolvedUser.username,
        otp,
        error: 'Invalid verification code',
        googleChallenge: retryChallenge,
        googleAccountLabel: resolvedUser.email || resolvedUser.username,
        qrSetupUrl: getInteractionQrSetupUrl(uid, resolvedUser.id),
      }));
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
