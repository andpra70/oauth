const storageKey = 'ecosystem.oidc.session.v1';
const legacyStorageKey = 'ecosystem.oauth.session.v1';

function base64url(bytes) {
  let value = '';
  for (const byte of bytes) value += String.fromCharCode(byte);
  return btoa(value).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

const randomString = (size = 32) => base64url(crypto.getRandomValues(new Uint8Array(size)));

async function challengeFor(verifier) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
  return base64url(new Uint8Array(digest));
}

function read() {
  try { return JSON.parse(sessionStorage.getItem(storageKey) || '{}'); } catch { return {}; }
}

function write(value) {
  sessionStorage.setItem(storageKey, JSON.stringify(value));
  return value;
}

const endpoint = (issuer, path) => `${String(issuer).replace(/\/+$/, '')}/${String(path).replace(/^\/+/, '')}`;

function cleanUrl(raw = window.location.href) {
  const url = new URL(raw, window.location.href);
  for (const key of ['code', 'state', 'iss', 'scope', 'authuser', 'prompt', 'error', 'error_description']) url.searchParams.delete(key);
  return url.toString();
}

async function tokenRequest(config, body) {
  const response = await fetch(endpoint(config.issuer, 'token'), {
    method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body,
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.error_description || payload.error || 'Token request failed');
  return payload;
}

const tokenExpiry = (tokens) => Date.now() + Number(tokens.expires_in || 3600) * 1000;

export function createOidcClient(input = {}) {
  const config = {
    issuer: String(input.issuer || window.location.origin).replace(/\/+$/, ''),
    clientId: input.clientId || 'fileserver-web',
    scope: input.scope || 'openid profile email offline_access',
    redirectUri: input.redirectUri || cleanUrl(),
    postLogoutRedirectUri: input.postLogoutRedirectUri || cleanUrl(),
  };
  let refreshInFlight = null;
  let initialization = null;
  let callbackInFlight = null;

  function getSession() {
    const session = read();
    if (!session.tokens?.access_token) return null;
    return {
      accessToken: session.tokens.access_token,
      refreshToken: session.tokens.refresh_token || '',
      idToken: session.tokens.id_token || '',
      expiresAt: new Date(Number(session.expiresAt || 0)).toISOString(),
      user: session.user || null,
      issuer: config.issuer,
      audience: config.clientId,
    };
  }

  const getUser = () => getSession()?.user || null;
  const isAuthenticated = () => Boolean(read().tokens?.access_token && Number(read().expiresAt || 0) > Date.now());

  function clear(reason = 'logout') {
    sessionStorage.removeItem(storageKey);
    window.dispatchEvent(new CustomEvent('oauth:logout', { detail: { reason } }));
  }

  async function refresh() {
    if (refreshInFlight) return refreshInFlight;
    refreshInFlight = (async () => {
      const session = read();
      if (!session.tokens?.refresh_token) throw new Error('Sessione OIDC non disponibile');
      const tokens = await tokenRequest(config, new URLSearchParams({
        grant_type: 'refresh_token', client_id: config.clientId, refresh_token: session.tokens.refresh_token,
      }));
      const next = write({
        ...session,
        tokens: { ...session.tokens, ...tokens, refresh_token: tokens.refresh_token || session.tokens.refresh_token },
        expiresAt: tokenExpiry(tokens),
      });
      return next.tokens.access_token;
    })().catch((error) => { clear('refresh_failed'); throw error; })
      .finally(() => { refreshInFlight = null; });
    return refreshInFlight;
  }

  async function getAccessToken() {
    if (callbackInFlight) await callbackInFlight;
    const session = read();
    if (session.tokens?.access_token && Number(session.expiresAt || 0) > Date.now() + 30_000) return session.tokens.access_token;
    return refresh();
  }

  async function loadUser({ emit = true } = {}) {
    const accessToken = await getAccessToken();
    const response = await fetch(endpoint(config.issuer, 'me'), { headers: { authorization: `Bearer ${accessToken}` } });
    const user = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(user.error_description || user.error || 'UserInfo non disponibile');
    write({ ...read(), user });
    if (emit) window.dispatchEvent(new CustomEvent('oauth:token', { detail: { user, source: 'oidc' } }));
    return user;
  }

  async function handleCallback() {
    const url = new URL(window.location.href);
    const oauthError = url.searchParams.get('error');
    if (oauthError) {
      const message = url.searchParams.get('error_description') || oauthError;
      window.history.replaceState({}, document.title, cleanUrl());
      throw new Error(message);
    }
    const code = url.searchParams.get('code');
    if (!code) return false;
    const session = read();
    if (!session.verifier || url.searchParams.get('state') !== session.state) throw new Error('Stato PKCE non valido');
    const tokens = await tokenRequest(config, new URLSearchParams({
      grant_type: 'authorization_code', client_id: config.clientId, code,
      redirect_uri: session.redirectUri || config.redirectUri, code_verifier: session.verifier,
    }));
    const returnTo = session.returnTo || cleanUrl();
    write({ tokens, expiresAt: tokenExpiry(tokens), user: null });
    window.history.replaceState({}, document.title, returnTo);
    return true;
  }

  function initialize() {
    if (!initialization) initialization = (async () => {
      sessionStorage.removeItem(legacyStorageKey);
      callbackInFlight ||= handleCallback();
      await callbackInFlight;
      if (!read().tokens?.access_token) return null;
      return loadUser();
    })();
    return initialization;
  }

  async function login(method = '') {
    const verifier = randomString(48);
    const state = randomString(24);
    const redirectUri = cleanUrl();
    write({ verifier, state, redirectUri, returnTo: redirectUri });
    const url = new URL(endpoint(config.issuer, 'auth'));
    Object.entries({ client_id: config.clientId, redirect_uri: redirectUri, response_type: 'code', scope: config.scope,
      code_challenge: await challengeFor(verifier), code_challenge_method: 'S256', state }).forEach(([key, value]) => url.searchParams.set(key, value));
    if (['account', 'passkey', 'google'].includes(method)) url.searchParams.set('login_method', method);
    window.location.assign(url.toString());
  }

  async function revoke(token, hint) {
    if (!token) return;
    await fetch(endpoint(config.issuer, 'token/revocation'), {
      method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ token, token_type_hint: hint, client_id: config.clientId }),
    }).catch(() => {});
  }

  async function logout() {
    const session = read();
    await Promise.all([revoke(session.tokens?.access_token, 'access_token'), revoke(session.tokens?.refresh_token, 'refresh_token')]);
    clear('logout');
    const url = new URL(endpoint(config.issuer, 'session/end'));
    url.searchParams.set('client_id', config.clientId);
    url.searchParams.set('post_logout_redirect_uri', config.postLogoutRedirectUri);
    if (session.tokens?.id_token) url.searchParams.set('id_token_hint', session.tokens.id_token);
    window.location.assign(url.toString());
  }

  return { config, initialize, refresh, getAccessToken, getSession, getUser, isAuthenticated, loadUser, login, logout };
}
