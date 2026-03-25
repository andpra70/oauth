const appConfig = window.__APP_CONFIG__ || {};
const baseUrl = new URL(appConfig.baseHref || document.baseURI, window.location.origin);
const storageKey = 'oauth-example3';

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

function defaultIssuer() {
  return appConfig.issuer || new URL('.', baseUrl).toString().replace(/\/$/, '');
}

function base64url(bytes) {
  let value = '';
  for (const byte of bytes) value += String.fromCharCode(byte);
  return btoa(value).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function randomString(size) {
  const bytes = crypto.getRandomValues(new Uint8Array(size));
  return base64url(bytes);
}

async function sha256(text) {
  const input = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest('SHA-256', input);
  return base64url(new Uint8Array(digest));
}

function loadSession() {
  return JSON.parse(sessionStorage.getItem(storageKey) || '{}');
}

function saveSession(data) {
  sessionStorage.setItem(storageKey, JSON.stringify(data));
}

function clearSession() {
  sessionStorage.removeItem(storageKey);
}

function defaultConfig() {
  return {
    issuer: defaultIssuer(),
    clientId: 'fileserver-web',
    redirectUri: appPath('example3/callback'),
    scope: 'openid profile email offline_access',
  };
}

async function exchangeCode(code, state) {
  const saved = loadSession();
  if (!saved.verifier || saved.state !== state || !saved.config) {
    throw new Error('Sessione PKCE mancante o non valida.');
  }

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

  saveSession({ ...saved, tokens: payload });
  return payload;
}

async function fetchProfile() {
  const saved = loadSession();
  const config = { ...defaultConfig(), ...(saved.config || {}) };
  const accessToken = saved.tokens?.access_token;
  if (!accessToken) {
    throw new Error('Access token non disponibile.');
  }

  const response = await fetch(issuerEndpoint(config.issuer, 'me'), {
    headers: {
      authorization: `Bearer ${accessToken}`,
    },
  });

  const payload = await response.json();
  if (!response.ok) {
    throw new Error(payload.error_description || payload.error || 'UserInfo non disponibile.');
  }

  return payload;
}

async function startLoginFlow() {
  const config = { ...defaultConfig(), ...(loadSession().config || {}) };
  const verifier = randomString(48);
  const state = randomString(24);
  const challenge = await sha256(verifier);

  saveSession({ ...loadSession(), verifier, state, config });

  const url = new URL(issuerEndpoint(config.issuer, 'auth'));
  url.searchParams.set('client_id', config.clientId);
  url.searchParams.set('redirect_uri', resolveBrowserUrl(config.redirectUri));
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('scope', config.scope || 'openid');
  url.searchParams.set('code_challenge', challenge);
  url.searchParams.set('code_challenge_method', 'S256');
  url.searchParams.set('state', state);
  window.location.assign(url.toString());
}

function startLogoutFlow() {
  const saved = loadSession();
  const config = { ...defaultConfig(), ...(saved.config || {}) };
  clearSession();

  const url = new URL(issuerEndpoint(config.issuer, 'session/end'));
  url.searchParams.set('client_id', config.clientId || 'fileserver-web');
  url.searchParams.set('post_logout_redirect_uri', resolveBrowserUrl(appPath('example3')));
  url.searchParams.set('state', 'example3-session-cleared');
  window.location.assign(url.toString());
}

const OAuthProfileCard = React.forwardRef(function OAuthProfileCard({ onProfileLoaded }, ref) {
  const [status, setStatus] = React.useState('Verifica sessione in corso...');
  const [error, setError] = React.useState('');
  const [profile, setProfile] = React.useState(null);
  const [busy, setBusy] = React.useState(true);

  React.useEffect(() => {
    let active = true;

    async function bootstrap() {
      try {
        const params = new URLSearchParams(window.location.search);

        if (params.get('state') === 'example3-session-cleared' && !params.get('code') && !params.get('error')) {
          window.history.replaceState({}, document.title, appPath('example3'));
          if (active) {
            setProfile(null);
            onProfileLoaded?.(null);
            setStatus('Sessione chiusa. Premi login per autenticarti di nuovo.');
            setBusy(false);
          }
          return;
        }

        if (params.get('error')) {
          throw new Error(params.get('error_description') || params.get('error'));
        }

        const code = params.get('code');
        const state = params.get('state');
        if (code && state) {
          if (active) setStatus('Callback ricevuto. Completo il token exchange...');
          await exchangeCode(code, state);
          if (active) {
            window.history.replaceState({}, document.title, appPath('example3'));
          }
          const me = await fetchProfile();
          if (!active) return;
          setProfile(me);
          onProfileLoaded?.(me);
          setStatus('Utente autenticato. Profilo caricato da /me.');
          setBusy(false);
          return;
        }

        const me = await fetchProfile();
        if (!active) return;
        setProfile(me);
        onProfileLoaded?.(me);
        setStatus('Utente autenticato.');
        setBusy(false);
      } catch (err) {
        if (!active) return;
        setProfile(null);
        onProfileLoaded?.(null);
        setError('');
        if (String(err?.message || '').includes('Access token non disponibile')) {
          setStatus('Utente non loggato.');
          setBusy(false);
          return;
        }
        if (String(err?.message || '').includes('UserInfo non disponibile')) {
          setStatus('Sessione non valida. Esegui di nuovo il login.');
          setBusy(false);
          return;
        }
        setError(err?.message || 'Errore nel caricamento del profilo.');
        setStatus('Impossibile determinare lo stato utente.');
        setBusy(false);
      }
    }

    bootstrap();
    return () => {
      active = false;
    };
  }, [onProfileLoaded]);

  React.useImperativeHandle(ref, () => ({
    getProfile() {
      return profile;
    },
  }), [profile]);

  async function handleLogin() {
    setBusy(true);
    setError('');
    setStatus('Redirect al provider OAuth...');
    await startLoginFlow();
  }

  function handleLogout() {
    setBusy(true);
    setError('');
    setStatus('Logout in corso...');
    startLogoutFlow();
  }

  const avatarUrl = profile?.picture || profile?.avatar_url || '';
  const avatarLabel = profile ? (profile.preferred_username || profile.email || profile.sub || 'U') : 'U';

  return (
    <section className="oauth-widget">
      {avatarUrl ? (
        <img className="session-avatar" src={avatarUrl} alt={avatarLabel} />
      ) : (
        <div className="session-avatar placeholder" aria-hidden="true">{avatarLabel.slice(0, 1).toUpperCase()}</div>
      )}
      <div className="session-inline">
        <span className={`session-text ${error ? 'error' : ''}`}>
          {profile ? (profile.preferred_username || profile.email || profile.sub || 'Utente') : (error || 'Non autenticato')}
        </span>
        {profile ? (
          <button className="secondary compact" onClick={handleLogout} disabled={busy}>Logout</button>
        ) : (
          <button className="primary compact" onClick={handleLogin} disabled={busy}>Login</button>
        )}
      </div>
      {busy ? <span className="session-pending">...</span> : null}
    </section>
  );
});

function Example3App() {
  const [profile, setProfile] = React.useState(null);
  const widgetRef = React.useRef(null);

  function handleReadProfile() {
    setProfile(widgetRef.current?.getProfile?.() || null);
  }

  return (
    <main className="example3-shell">
      <section className="hero hero-compact">
        <OAuthProfileCard ref={widgetRef} onProfileLoaded={setProfile} />
      </section>

      <section className="exposed-panel">
        <h2>Profilo esposto dal componente</h2>
        <div className="exposed-actions">
          <button className="primary compact" onClick={handleReadProfile}>Leggi profilo dal componente</button>
        </div>
        <pre>{JSON.stringify(profile, null, 2)}</pre>
      </section>
    </main>
  );
}

ReactDOM.createRoot(document.getElementById('app')).render(<Example3App />);
