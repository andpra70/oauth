const storageKey = 'oauth-console.pkce';
const appConfig = window.__APP_CONFIG__ || {};
const baseUrl = new URL(appConfig.baseHref || document.baseURI, window.location.origin);

const el = {
  issuer: document.querySelector('#issuer'),
  clientId: document.querySelector('#clientId'),
  redirectUri: document.querySelector('#redirectUri'),
  scope: document.querySelector('#scope'),
  setupToken: document.querySelector('#setupToken'),
  username: document.querySelector('#username'),
  startAuth: document.querySelector('#startAuth'),
  loadQr: document.querySelector('#loadQr'),
  clearState: document.querySelector('#clearState'),
  status: document.querySelector('#status'),
  qrImage: document.querySelector('#qrImage'),
  qrHint: document.querySelector('#qrHint'),
  otpauth: document.querySelector('#otpauth'),
  tokenOutput: document.querySelector('#tokenOutput'),
  meOutput: document.querySelector('#meOutput'),
};

function appUrl(path = '') {
  return new URL(String(path).replace(/^\/+/, ''), baseUrl).toString();
}

function appPath(path = '') {
  return new URL(String(path).replace(/^\/+/, ''), baseUrl).pathname;
}

function resolveBrowserUrl(value) {
  const raw = String(value || '').trim();
  if (!raw) return '';
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(raw)) return raw;
  if (raw.startsWith('/')) return new URL(raw, window.location.origin).toString();
  return new URL(raw, baseUrl).toString();
}

function issuerEndpoint(issuer, path) {
  return new URL(String(path).replace(/^\/+/, ''), `${String(issuer || '').replace(/\/+$/, '')}/`).toString();
}

function setStatus(message, type = 'info') {
  el.status.textContent = message;
  el.status.classList.toggle('error', type === 'error');
}

function getDefaults() {
  return {
    issuer: new URL('.', baseUrl).toString().replace(/\/$/, ''),
    clientId: 'fileserver-web',
    redirectUri: appPath('app/callback'),
    scope: 'openid profile email offline_access',
    username: 'admin',
    setupToken: '',
  };
}

function readConfig() {
  return {
    issuer: el.issuer.value.trim().replace(/\/+$/, ''),
    clientId: el.clientId.value.trim(),
    redirectUri: el.redirectUri.value.trim(),
    scope: el.scope.value.trim(),
    setupToken: el.setupToken.value.trim(),
    username: el.username.value.trim(),
  };
}

function writeConfig(config) {
  el.issuer.value = config.issuer;
  el.clientId.value = config.clientId;
  el.redirectUri.value = config.redirectUri;
  el.scope.value = config.scope;
  el.setupToken.value = config.setupToken;
  el.username.value = config.username;
}

function encodeBase64Url(buffer) {
  const bytes = new Uint8Array(buffer);
  let value = '';
  for (const byte of bytes) {
    value += String.fromCharCode(byte);
  }
  return btoa(value).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function randomString(size = 32) {
  const bytes = crypto.getRandomValues(new Uint8Array(size));
  return encodeBase64Url(bytes);
}

async function sha256(value) {
  return crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
}

async function createPkcePair() {
  const verifier = randomString(48);
  const challenge = encodeBase64Url(await sha256(verifier));
  return { verifier, challenge };
}

async function startAuthorization() {
  const config = readConfig();
  if (!config.issuer || !config.clientId || !config.redirectUri) {
    setStatus('Issuer, client ID e redirect URI sono obbligatori.', 'error');
    return;
  }

  el.startAuth.disabled = true;
  try {
    const { verifier, challenge } = await createPkcePair();
    const state = randomString(24);
    sessionStorage.setItem(storageKey, JSON.stringify({ verifier, state, config }));
    const redirectUri = resolveBrowserUrl(config.redirectUri);

    const url = new URL(issuerEndpoint(config.issuer, 'auth'));
    url.searchParams.set('client_id', config.clientId);
    url.searchParams.set('redirect_uri', redirectUri);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('scope', config.scope || 'openid');
    url.searchParams.set('code_challenge', challenge);
    url.searchParams.set('code_challenge_method', 'S256');
    url.searchParams.set('state', state);

    setStatus('Redirect verso il provider in corso...');
    window.location.assign(url);
  } catch (error) {
    setStatus(error.message || 'Errore durante la preparazione del flow.', 'error');
  } finally {
    el.startAuth.disabled = false;
  }
}

async function exchangeCode(code, state) {
  const raw = sessionStorage.getItem(storageKey);
  if (!raw) {
    throw new Error('Stato PKCE mancante in sessionStorage.');
  }

  const saved = JSON.parse(raw);
  if (saved.state !== state) {
    throw new Error('State non valido.');
  }

  writeConfig({ ...getDefaults(), ...saved.config });

  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    client_id: saved.config.clientId,
    code,
    redirect_uri: resolveBrowserUrl(saved.config.redirectUri),
    code_verifier: saved.verifier,
  });

  const response = await fetch(issuerEndpoint(saved.config.issuer, 'token'), {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
    },
    body,
  });

  const payload = await response.json();
  if (!response.ok) {
    throw new Error(payload.error_description || payload.error || 'Token exchange fallito.');
  }

  el.tokenOutput.textContent = JSON.stringify(payload, null, 2);
  if (payload.access_token) {
    await loadUserInfo(saved.config.issuer, payload.access_token);
  }

  setStatus('Autenticazione completata. Token ottenuti con successo.');
  window.history.replaceState({}, document.title, appPath('app'));
}

async function loadUserInfo(issuer, accessToken) {
  const response = await fetch(issuerEndpoint(issuer, 'me'), {
    headers: {
      authorization: `Bearer ${accessToken}`,
    },
  });

  const payload = await response.json();
  if (!response.ok) {
    throw new Error(payload.error_description || payload.error || 'UserInfo non disponibile.');
  }

  el.meOutput.textContent = JSON.stringify(payload, null, 2);
}

async function loadQr() {
  const config = readConfig();
  if (!config.setupToken || !config.username) {
    setStatus('Setup token e username admin sono obbligatori per leggere il QR.', 'error');
    return;
  }

  el.loadQr.disabled = true;
  try {
    const url = new URL(issuerEndpoint(config.issuer, `setup/2fa-qr/${encodeURIComponent(config.username)}.json`));
    url.searchParams.set('token', config.setupToken);

    const response = await fetch(url);
    const payload = await response.json();
    if (!response.ok) {
      throw new Error(payload.error || 'QR non disponibile.');
    }

    el.qrImage.hidden = false;
    el.qrImage.src = payload.dataUrl;
    el.otpauth.textContent = payload.otpauthUrl;
    el.qrHint.textContent = `Scansiona il QR con l'app TOTP e poi completa il login browser-based su /interaction/:uid.`;
    setStatus('QR TOTP caricato.');
  } catch (error) {
    setStatus(error.message || 'Errore nel caricamento del QR.', 'error');
  } finally {
    el.loadQr.disabled = false;
  }
}

function clearState() {
  const config = readConfig();
  sessionStorage.removeItem(storageKey);
  el.tokenOutput.textContent = 'Nessun token disponibile.';
  el.meOutput.textContent = 'Nessun profilo caricato.';
  el.qrImage.hidden = true;
  el.qrImage.removeAttribute('src');
  el.otpauth.textContent = 'Nessun QR caricato.';
  setStatus('Pulizia sessione in corso...');

  const logoutUrl = new URL(issuerEndpoint(config.issuer || getDefaults().issuer, 'session/end'));
  logoutUrl.searchParams.set('client_id', config.clientId || 'fileserver-web');
  logoutUrl.searchParams.set('post_logout_redirect_uri', resolveBrowserUrl(appPath('app')));
  logoutUrl.searchParams.set('state', 'session-cleared');
  window.location.assign(logoutUrl);
}

async function handleCallback() {
  const params = new URLSearchParams(window.location.search);
  if (params.get('state') === 'session-cleared' && !params.get('code') && !params.get('error')) {
    setStatus('Sessione locale e sessione OIDC pulite.');
    window.history.replaceState({}, document.title, appPath('app'));
    return;
  }

  if (params.get('error')) {
    setStatus(`${params.get('error')}: ${params.get('error_description') || 'autorizzazione fallita'}`, 'error');
    return;
  }

  const code = params.get('code');
  const state = params.get('state');
  if (!code || !state) {
    return;
  }

  setStatus('Callback ricevuto. Scambio del code in corso...');
  try {
    await exchangeCode(code, state);
  } catch (error) {
    setStatus(error.message || 'Errore durante il token exchange.', 'error');
  }
}

function bootstrap() {
  writeConfig(getDefaults());
  el.startAuth.addEventListener('click', startAuthorization);
  el.loadQr.addEventListener('click', loadQr);
  el.clearState.addEventListener('click', clearState);
  handleCallback();
}

bootstrap();
