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

const styles = {
  shell: {
    position: 'fixed',
    top: '16px',
    right: '16px',
    zIndex: 2147483647,
    pointerEvents: 'none',
  },
  panel: {
    pointerEvents: 'auto',
    display: 'inline-flex',
    alignItems: 'center',
    gap: '10px',
    minHeight: '46px',
    maxWidth: 'min(92vw, 360px)',
    padding: '4px 6px 4px 4px',
    border: '1px solid rgba(15, 23, 42, 0.08)',
    background: 'rgba(255, 255, 255, 0.96)',
    boxShadow: '0 10px 28px rgba(15, 23, 42, 0.16)',
    color: '#0f172a',
    fontFamily: 'ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
    whiteSpace: 'nowrap',
  },
  avatar: {
    width: '30px',
    height: '30px',
    objectFit: 'cover',
    flex: '0 0 auto',
    background: '#e2e8f0',
    border: '1px solid rgba(15, 23, 42, 0.08)',
  },
  avatarPlaceholder: {
    display: 'inline-flex',
    alignItems: 'center',
    justifyContent: 'center',
    fontSize: '12px',
    fontWeight: 700,
    color: '#334155',
  },
  content: {
    minWidth: 0,
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
  },
  text: {
    maxWidth: '180px',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    fontSize: '13px',
    fontWeight: 600,
    color: '#0f172a',
  },
  textMuted: {
    color: '#64748b',
  },
  button: {
    border: 0,
    padding: '7px 11px',
    font: 'inherit',
    fontSize: '12px',
    fontWeight: 700,
    cursor: 'pointer',
    flex: '0 0 auto',
  },
  loginButton: {
    background: '#0f766e',
    color: '#ffffff',
  },
  logoutButton: {
    background: '#f59e0b',
    color: '#111827',
  },
  pending: {
    fontSize: '11px',
    color: '#64748b',
    fontWeight: 700,
  },
};

function emitProfileEvent(profile) {
  window.dispatchEvent(new CustomEvent('oauth-widget:profile', {
    detail: { profile: profile || null },
  }));
}

function OAuthProfileCard() {
  const [status, setStatus] = React.useState('Verifica sessione');
  const [profile, setProfile] = React.useState(null);
  const [busy, setBusy] = React.useState(true);

  React.useEffect(() => {
    let active = true;

    async function syncSession() {
      try {
        const params = new URLSearchParams(window.location.search);

        if (params.get('state') === 'example3-session-cleared' && !params.get('code') && !params.get('error')) {
          window.history.replaceState({}, document.title, appPath('example3'));
          if (active) {
            setProfile(null);
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
          setStatus('Utente autenticato. Profilo caricato da /me.');
          setBusy(false);
          return;
        }

        const me = await fetchProfile();
        if (!active) return;
        setProfile(me);
        setStatus('Autenticato');
        setBusy(false);
      } catch (err) {
        if (!active) return;
        setProfile(null);
        if (String(err?.message || '').includes('Access token non disponibile')) {
          setStatus('Non autenticato');
          setBusy(false);
          return;
        }
        if (String(err?.message || '').includes('UserInfo non disponibile')) {
          setStatus('Sessione scaduta');
          setBusy(false);
          return;
        }
        setStatus('Errore sessione');
        setBusy(false);
      }
    }

    syncSession();

    function handlePageShow() {
      if (!active) return;
      setBusy(true);
      syncSession();
    }

    function handlePopState() {
      if (!active) return;
      setBusy(true);
      syncSession();
    }

    window.addEventListener('pageshow', handlePageShow);
    window.addEventListener('popstate', handlePopState);

    return () => {
      active = false;
      window.removeEventListener('pageshow', handlePageShow);
      window.removeEventListener('popstate', handlePopState);
    };
  }, []);

  React.useEffect(() => {
    emitProfileEvent(profile);
  }, [profile]);

  async function handleLogin() {
    setBusy(true);
    setStatus('Redirect login');
    await startLoginFlow();
  }

  function handleLogout() {
    setBusy(true);
    setStatus('Logout');
    startLogoutFlow();
  }

  const avatarUrl = profile?.picture || profile?.avatar_url || '';
  const identityLabel = profile?.email || profile?.preferred_username || profile?.sub || status;
  const avatarLabel = profile ? (profile.preferred_username || profile.email || profile.sub || 'U') : 'U';

  return (
    <section style={styles.shell}>
      <div style={styles.panel}>
        {avatarUrl ? (
          <img style={styles.avatar} src={avatarUrl} alt={avatarLabel} />
        ) : (
          <div style={{ ...styles.avatar, ...styles.avatarPlaceholder }} aria-hidden="true">{avatarLabel.slice(0, 1).toUpperCase()}</div>
        )}
        <div style={styles.content}>
          <span style={{ ...styles.text, ...(profile ? null : styles.textMuted) }}>
            {identityLabel}
          </span>
          {profile ? (
            <button style={{ ...styles.button, ...styles.logoutButton, ...(busy ? { opacity: 0.7, cursor: 'wait' } : null) }} onClick={handleLogout} disabled={busy}>Logout</button>
          ) : (
            <button style={{ ...styles.button, ...styles.loginButton, ...(busy ? { opacity: 0.7, cursor: 'wait' } : null) }} onClick={handleLogin} disabled={busy}>Login</button>
          )}
        </div>
        {busy ? <span style={styles.pending}>...</span> : null}
      </div>
    </section>
  );
}

function Example3App() {
  return <OAuthProfileCard />;
}

ReactDOM.createRoot(document.getElementById('app')).render(<Example3App />);
