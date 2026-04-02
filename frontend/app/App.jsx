import { useEffect, useMemo, useState } from 'react';
import { appPath, issuerEndpoint, resolveBrowserUrl } from '../shared/api.js';

const storageKey = 'oauth-console.pkce';

function issuerFromCurrentContext() {
  return new URL(appPath(''), window.location.origin).toString().replace(/\/$/, '');
}

function getDefaults() {
  return {
    issuer: issuerFromCurrentContext(),
    clientId: 'fileserver-web',
    redirectUri: appPath('app/callback'),
    callbackUrl: '',
    scope: 'openid profile email offline_access',
    username: 'admin',
    setupToken: '',
  };
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

function base64UrlToArrayBuffer(value) {
  const normalized = String(value || '').replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized + '==='.slice((normalized.length + 3) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

function arrayBufferToBase64Url(value) {
  const bytes = new Uint8Array(value);
  let binary = '';
  for (let i = 0; i < bytes.length; i += 1) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

async function sha256(value) {
  return crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
}

async function createPkcePair() {
  const verifier = randomString(48);
  const challenge = encodeBase64Url(await sha256(verifier));
  return { verifier, challenge };
}

export default function App() {
  const initial = useMemo(() => getDefaults(), []);
  const [config, setConfig] = useState(initial);
  const [busyAction, setBusyAction] = useState('');
  const [status, setStatus] = useState({
    type: 'info',
    message: 'Pronto. Avvia il flow oppure carica il QR TOTP.',
  });
  const [tokenOutput, setTokenOutput] = useState('Nessun token disponibile.');
  const [meOutput, setMeOutput] = useState('Nessun profilo caricato.');
  const [qrImage, setQrImage] = useState('');
  const [qrHint, setQrHint] = useState('Il QR è protetto dal setup token. Dopo il bootstrap iniziale puoi usarlo con una app TOTP e completare il login nelle schermate `/interaction/:uid`.');
  const [otpauth, setOtpauth] = useState('Nessun QR caricato.');

  function updateField(field, value) {
    setConfig((prev) => ({ ...prev, [field]: value }));
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

    setMeOutput(JSON.stringify(payload, null, 2));
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

    setConfig({ ...getDefaults(), ...saved.config });

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

    setTokenOutput(JSON.stringify(payload, null, 2));
    if (payload.access_token) {
      await loadUserInfo(saved.config.issuer, payload.access_token);
    }

    setStatus({ type: 'info', message: 'Autenticazione completata. Token ottenuti con successo.' });
    window.history.replaceState({}, document.title, appPath('app'));
  }

  useEffect(() => {
    async function handleCallback() {
      const params = new URLSearchParams(window.location.search);
      if (params.get('state') === 'session-cleared' && !params.get('code') && !params.get('error')) {
        setStatus({ type: 'info', message: 'Sessione locale e sessione OIDC pulite.' });
        window.history.replaceState({}, document.title, appPath('app'));
        return;
      }

      if (params.get('error')) {
        setStatus({
          type: 'error',
          message: `${params.get('error')}: ${params.get('error_description') || 'autorizzazione fallita'}`,
        });
        return;
      }

      const code = params.get('code');
      const state = params.get('state');
      if (!code || !state) return;

      setStatus({ type: 'info', message: 'Callback ricevuto. Scambio del code in corso...' });
      try {
        await exchangeCode(code, state);
      } catch (error) {
        setStatus({ type: 'error', message: error.message || 'Errore durante il token exchange.' });
      }
    }

    handleCallback();
  }, []);

  async function startAuthorization() {
    if (!config.issuer || !config.clientId || !config.redirectUri) {
      setStatus({ type: 'error', message: 'Issuer, client ID e redirect URI sono obbligatori.' });
      return;
    }

    setBusyAction('auth');
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
      if (config.callbackUrl) {
        url.searchParams.set('callbackUrl', resolveBrowserUrl(config.callbackUrl));
      }
      url.searchParams.set('code_challenge', challenge);
      url.searchParams.set('code_challenge_method', 'S256');
      url.searchParams.set('state', state);

      setStatus({ type: 'info', message: 'Redirect verso il provider in corso...' });
      window.location.assign(url);
    } catch (error) {
      setStatus({ type: 'error', message: error.message || 'Errore durante la preparazione del flow.' });
    } finally {
      setBusyAction('');
    }
  }

  async function loadQr() {
    if (!config.setupToken || !config.username) {
      setStatus({ type: 'error', message: 'Setup token e username admin sono obbligatori per leggere il QR.' });
      return;
    }

    setBusyAction('qr');
    try {
      const url = new URL(issuerEndpoint(config.issuer, `setup/2fa-qr/${encodeURIComponent(config.username)}.json`));
      url.searchParams.set('token', config.setupToken);

      const response = await fetch(url);
      const payload = await response.json();
      if (!response.ok) {
        throw new Error(payload.error || 'QR non disponibile.');
      }

      setQrImage(payload.dataUrl);
      setOtpauth(payload.otpauthUrl);
      setQrHint("Scansiona il QR con l'app TOTP e poi completa il login browser-based su /interaction/:uid.");
      setStatus({ type: 'info', message: 'QR TOTP caricato.' });
    } catch (error) {
      setStatus({ type: 'error', message: error.message || 'Errore nel caricamento del QR.' });
    } finally {
      setBusyAction('');
    }
  }

  async function registerPasskey() {
    if (!window.PublicKeyCredential || !navigator.credentials) {
      setStatus({ type: 'error', message: 'Passkey non supportato da questo browser.' });
      return;
    }
    if (!config.setupToken || !config.username) {
      setStatus({ type: 'error', message: 'Setup token e username sono obbligatori per registrare una passkey.' });
      return;
    }

    setBusyAction('passkey');
    try {
      const optionsUrl = new URL(issuerEndpoint(config.issuer, `setup/passkeys/${encodeURIComponent(config.username)}/options`));
      optionsUrl.searchParams.set('token', config.setupToken);
      const optionsResponse = await fetch(optionsUrl, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
      });
      const optionsPayload = await optionsResponse.json();
      if (!optionsResponse.ok) {
        throw new Error(optionsPayload.error || 'Impossibile iniziare la registrazione passkey.');
      }

      const publicKey = optionsPayload.publicKey;
      publicKey.challenge = base64UrlToArrayBuffer(publicKey.challenge);
      if (publicKey.user?.id) {
        publicKey.user.id = base64UrlToArrayBuffer(publicKey.user.id);
      }
      if (Array.isArray(publicKey.excludeCredentials)) {
        publicKey.excludeCredentials = publicKey.excludeCredentials.map((item) => ({
          ...item,
          id: base64UrlToArrayBuffer(item.id),
        }));
      }

      const credential = await navigator.credentials.create({ publicKey });
      if (!credential) {
        throw new Error('Creazione passkey annullata.');
      }

      const registrationPayload = {
        token: optionsPayload.token,
        credential: {
          id: credential.id,
          rawId: arrayBufferToBase64Url(credential.rawId),
          type: credential.type,
          response: {
            attestationObject: arrayBufferToBase64Url(credential.response.attestationObject),
            clientDataJSON: arrayBufferToBase64Url(credential.response.clientDataJSON),
            transports: credential.response.getTransports ? credential.response.getTransports() : [],
          },
          authenticatorAttachment: credential.authenticatorAttachment || null,
          clientExtensionResults: credential.getClientExtensionResults ? credential.getClientExtensionResults() : {},
        },
      };

      const verifyUrl = new URL(issuerEndpoint(config.issuer, `setup/passkeys/${encodeURIComponent(config.username)}/verify`));
      verifyUrl.searchParams.set('token', config.setupToken);
      const verifyResponse = await fetch(verifyUrl, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(registrationPayload),
      });
      const verifyPayload = await verifyResponse.json();
      if (!verifyResponse.ok) {
        throw new Error(verifyPayload.error || 'Registrazione passkey fallita.');
      }

      setStatus({ type: 'info', message: `Passkey registrata per ${verifyPayload.username || config.username}.` });
    } catch (error) {
      setStatus({ type: 'error', message: error.message || 'Errore registrazione passkey.' });
    } finally {
      setBusyAction('');
    }
  }

  function clearState() {
    sessionStorage.removeItem(storageKey);
    setTokenOutput('Nessun token disponibile.');
    setMeOutput('Nessun profilo caricato.');
    setQrImage('');
    setOtpauth('Nessun QR caricato.');
    setStatus({ type: 'info', message: 'Pulizia sessione in corso...' });

    const logoutUrl = new URL(issuerEndpoint(config.issuer || getDefaults().issuer, 'session/end'));
    logoutUrl.searchParams.set('client_id', config.clientId || 'fileserver-web');
    logoutUrl.searchParams.set('post_logout_redirect_uri', resolveBrowserUrl(appPath('app')));
    logoutUrl.searchParams.set('state', 'session-cleared');
    window.location.assign(logoutUrl);
  }

  function openAuthWidget() {
    window.location.assign(issuerEndpoint(config.issuer || getDefaults().issuer, 'authWidget'));
  }

  function openUsersAdmin() {
    if (!config.setupToken) {
      setStatus({ type: 'error', message: 'Setup token obbligatorio per aprire la gestione utenti.' });
      return;
    }
    const url = new URL(issuerEndpoint(config.issuer || getDefaults().issuer, 'setup/users'));
    url.searchParams.set('token', config.setupToken);
    window.location.assign(url);
  }

  function openFlowDiagram() {
    window.location.assign(issuerEndpoint(config.issuer || getDefaults().issuer, 'flow-diagram'));
  }

  return (
    <main>
      <section className="hero">
        <div className="badge-row">
          <span className="badge">Authorization Code + PKCE</span>
          <span className="badge">TOTP</span>
          <span className="badge">Same container UI</span>
        </div>
        <h1>OAuth Sign-In Console</h1>
        <p>
          Questa pagina vive nello stesso container del provider OIDC. Avvia il flow di autenticazione,
          gestisce il callback, scambia il code con i token e mostra il QR TOTP dell'utente admin.
        </p>
      </section>

      <section className="grid">
        <section className="panel">
          <h2>Avvio flow</h2>
          <div className="fields">
            <div className="field">
              <label htmlFor="issuer">Issuer</label>
              <input id="issuer" value={config.issuer} onChange={(e) => updateField('issuer', e.target.value)} />
            </div>
            <div className="field">
              <label htmlFor="clientId">Client ID</label>
              <input id="clientId" value={config.clientId} onChange={(e) => updateField('clientId', e.target.value)} />
            </div>
            <div className="field full">
              <label htmlFor="redirectUri">Redirect URI</label>
              <input id="redirectUri" value={config.redirectUri} onChange={(e) => updateField('redirectUri', e.target.value)} />
            </div>
            <div className="field full">
              <label htmlFor="callbackUrl">Interaction callback URL</label>
              <input id="callbackUrl" value={config.callbackUrl} onChange={(e) => updateField('callbackUrl', e.target.value)} placeholder="http://localhost:8080/oauth/callback-state" />
            </div>
            <div className="field full">
              <label htmlFor="scope">Scope</label>
              <input id="scope" value={config.scope} onChange={(e) => updateField('scope', e.target.value)} />
            </div>
            <div className="field">
              <label htmlFor="setupToken">Setup token TOTP</label>
              <input id="setupToken" value={config.setupToken} onChange={(e) => updateField('setupToken', e.target.value)} placeholder="replace-with-bootstrap-token" />
            </div>
            <div className="field">
              <label htmlFor="username">Admin username</label>
              <input id="username" value={config.username} onChange={(e) => updateField('username', e.target.value)} />
            </div>
          </div>
          <div className="actions">
            <button className="primary" onClick={startAuthorization} disabled={busyAction === 'auth'}>Accedi con OAuth</button>
            <button className="secondary" onClick={loadQr} disabled={busyAction === 'qr'}>Mostra QR TOTP</button>
            <button className="secondary" onClick={registerPasskey} disabled={busyAction === 'passkey'}>Registra/Resetta Passkey</button>
            <button className="secondary" onClick={openUsersAdmin}>Admin</button>
            <button className="secondary" onClick={openFlowDiagram}>Mappa flussi OAuth</button>
            <button className="ghost" onClick={openAuthWidget}>Apri AuthWidget</button>
            <button className="ghost" onClick={clearState}>Pulisci sessione</button>
          </div>
          <div className={`status ${status.type === 'error' ? 'error' : ''}`.trim()}>{status.message}</div>
        </section>

        <section className="panel">
          <h2>QR e TOTP</h2>
          <div className="qr">
            {qrImage ? <img src={qrImage} alt="QR TOTP" /> : null}
            <div className="hint">{qrHint}</div>
            <pre>{otpauth}</pre>
          </div>
        </section>
      </section>

      <section className="grid">
        <section className="panel">
          <h3>Tokens</h3>
          <div className="tokens">
            <pre>{tokenOutput}</pre>
          </div>
        </section>
        <section className="panel">
          <h3>UserInfo</h3>
          <div className="meta">
            <pre>{meOutput}</pre>
          </div>
        </section>
      </section>
    </main>
  );
}
