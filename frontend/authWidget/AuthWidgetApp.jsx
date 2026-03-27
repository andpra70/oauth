import { useEffect, useRef, useState } from 'react';
import { appPath, defaultIssuer, issuerEndpoint, resolveBrowserUrl } from '../shared/api.js';

const storageKey = 'oauth-authWidget';
const oauthTransientParams = ['code', 'state', 'iss', 'scope', 'authuser', 'prompt', 'error', 'error_description'];

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

function readRuntimeConfig() {
  const fromWindow = (window.__AUTH_WIDGET_CONFIG__ && typeof window.__AUTH_WIDGET_CONFIG__ === 'object')
    ? window.__AUTH_WIDGET_CONFIG__
    : {};
  const params = new URLSearchParams(window.location.search);
  const fromWindowCtas = (fromWindow.ctas && typeof fromWindow.ctas === 'object') ? fromWindow.ctas : {};
  function parseBool(value, fallback) {
    if (value === undefined || value === null || value === '') return fallback;
    return !['0', 'false', 'no', 'off'].includes(String(value).trim().toLowerCase());
  }
  return {
    issuer: String(params.get('awIssuer') || fromWindow.issuer || '').trim(),
    clientId: String(params.get('awClientId') || fromWindow.clientId || '').trim(),
    redirectUri: String(params.get('awRedirectUri') || fromWindow.redirectUri || '').trim(),
    origin: String(params.get('awOrigin') || fromWindow.origin || '').trim(),
    postLogoutRedirectUri: String(params.get('awPostLogoutRedirectUri') || fromWindow.postLogoutRedirectUri || '').trim(),
    scope: String(params.get('awScope') || fromWindow.scope || '').trim(),
    ctas: {
      login: parseBool(params.get('awShowLogin'), parseBool(fromWindowCtas.login, true)),
      logout: parseBool(params.get('awShowLogout'), parseBool(fromWindowCtas.logout, true)),
      expand: parseBool(params.get('awShowExpand'), parseBool(fromWindowCtas.expand, true)),
      editProfile: parseBool(params.get('awShowEditProfile'), parseBool(fromWindowCtas.editProfile, true)),
    },
  };
}

function resolveWithOrigin(value, origin) {
  const raw = String(value || '').trim();
  if (!raw) return '';
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(raw)) return raw;
  const resolvedOrigin = origin ? resolveBrowserUrl(origin) : window.location.origin;
  if (!resolvedOrigin) return resolveBrowserUrl(raw);
  if (raw.startsWith('/')) return new URL(raw, resolvedOrigin).toString();
  return new URL(raw, `${resolvedOrigin.replace(/\/+$/g, '')}/`).toString();
}

function cleanupCurrentUrl() {
  const url = new URL(window.location.href);
  for (const key of oauthTransientParams) url.searchParams.delete(key);
  window.history.replaceState({}, document.title, `${url.pathname}${url.search}${url.hash}`);
}

function defaultConfig() {
  const runtime = readRuntimeConfig();
  const fallbackOrigin = runtime.origin || window.location.origin;
  const redirectUri = runtime.redirectUri
    ? resolveWithOrigin(runtime.redirectUri, fallbackOrigin)
    : resolveWithOrigin(appPath('authWidget/callback'), fallbackOrigin);
  const postLogoutRedirectUri = runtime.postLogoutRedirectUri
    ? resolveWithOrigin(runtime.postLogoutRedirectUri, fallbackOrigin)
    : resolveWithOrigin(appPath('authWidget'), fallbackOrigin);

  return {
    issuer: runtime.issuer || defaultIssuer(),
    clientId: runtime.clientId || 'fileserver-web',
    origin: fallbackOrigin,
    redirectUri,
    postLogoutRedirectUri,
    scope: runtime.scope || 'openid profile email offline_access',
    ctas: runtime.ctas,
  };
}

function profileFromPayload(payload) {
  if (!payload || typeof payload !== 'object') return null;
  const picture = payload.picture || payload.avatar_url || '';
  return {
    sub: payload.sub || '',
    preferred_username: payload.preferred_username || '',
    email: payload.email || '',
    picture,
    avatar_url: payload.avatar_url || picture || '',
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
    redirect_uri: resolveWithOrigin(saved.config.redirectUri, saved.config.origin || ''),
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

  return profileFromPayload(payload);
}

async function startLoginFlow() {
  const config = { ...defaultConfig(), ...(loadSession().config || {}) };
  config.redirectUri = resolveWithOrigin(config.redirectUri, config.origin || '');
  config.postLogoutRedirectUri = resolveWithOrigin(config.postLogoutRedirectUri, config.origin || '');
  const verifier = randomString(48);
  const state = randomString(24);
  const challenge = await sha256(verifier);

  saveSession({ ...loadSession(), verifier, state, config });

  const url = new URL(issuerEndpoint(config.issuer, 'auth'));
  url.searchParams.set('client_id', config.clientId);
  url.searchParams.set('redirect_uri', config.redirectUri);
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
  config.postLogoutRedirectUri = resolveWithOrigin(config.postLogoutRedirectUri, config.origin || '');
  clearSession();

  const url = new URL(issuerEndpoint(config.issuer, 'session/end'));
  url.searchParams.set('client_id', config.clientId || 'fileserver-web');
  url.searchParams.set('post_logout_redirect_uri', config.postLogoutRedirectUri);
  url.searchParams.set('state', 'authWidget-session-cleared');
  window.location.assign(url.toString());
}

const styles = {
  shell: {
    position: 'fixed',
    top: '0',
    right: '0',
    zIndex: 2147483647,
    pointerEvents: 'none',
  },
  panel: {
    pointerEvents: 'auto',
    width: 'min(88vw, 280px)',
    padding: '4px 6px',
    border: '1px solid rgba(15, 23, 42, 0.08)',
    background: 'rgba(255, 255, 255, 0.96)',
    boxShadow: '0 10px 28px rgba(15, 23, 42, 0.16)',
    color: '#0f172a',
    fontFamily: 'ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
    borderRadius: '6px',
  },
  row: {
    display: 'flex',
    alignItems: 'flex-start',
    gap: '6px',
  },
  avatar: {
    width: '20px',
    height: '20px',
    objectFit: 'cover',
    flex: '0 0 auto',
    background: '#e2e8f0',
    border: '1px solid rgba(15, 23, 42, 0.08)',
    borderRadius: '4px',
  },
  avatarButton: {
    border: 0,
    margin: 0,
    padding: 0,
    background: 'transparent',
    cursor: 'pointer',
    lineHeight: 0,
  },
  avatarPlaceholder: {
    display: 'inline-flex',
    alignItems: 'center',
    justifyContent: 'center',
    fontSize: '9px',
    fontWeight: 700,
    color: '#334155',
  },
  content: {
    display: 'flex',
    flex: '1 1 auto',
    alignItems: 'center',
    justifyContent: 'space-between',
    gap: '6px',
    minWidth: 0,
  },
  text: {
    maxWidth: '132px',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    fontSize: '10px',
    fontWeight: 600,
    color: '#0f172a',
  },
  textMuted: {
    color: '#64748b',
  },
  button: {
    border: '1px solid rgba(15, 23, 42, 0.1)',
    padding: '2px 6px',
    font: 'inherit',
    fontSize: '9px',
    fontWeight: 700,
    cursor: 'pointer',
    flex: '0 0 auto',
    borderRadius: '4px',
    background: '#f8fafc',
    color: '#0f172a',
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
    fontSize: '9px',
    color: '#64748b',
    fontWeight: 700,
  },
  status: {
    marginTop: '4px',
    fontSize: '9px',
    color: '#64748b',
  },
  body: {
    marginTop: '6px',
    borderTop: '1px solid rgba(15, 23, 42, 0.08)',
    paddingTop: '6px',
    display: 'grid',
    gap: '6px',
  },
  kvRow: {
    display: 'grid',
    gap: '4px',
    fontSize: '10px',
  },
  kvLabel: {
    color: '#64748b',
    fontWeight: 600,
  },
  input: {
    width: '100%',
    border: '1px solid rgba(15, 23, 42, 0.16)',
    borderRadius: '4px',
    padding: '4px 6px',
    fontSize: '10px',
    background: '#fff',
    color: '#0f172a',
  },
  ctaWrap: {
    display: 'flex',
    flexWrap: 'wrap',
    gap: '4px',
  },
};

function emitProfileEvent(profile) {
  window.dispatchEvent(new CustomEvent('oauth-widget:profile', {
    detail: { profile: profile || null },
  }));
}

function OAuthProfileCard() {
  const runtimeConfigRef = useRef(readRuntimeConfig());
  const [status, setStatus] = useState('');
  const [profile, setProfile] = useState(null);
  const [busy, setBusy] = useState(true);
  const [expanded, setExpanded] = useState(false);
  const [editMode, setEditMode] = useState(false);
  const [savingProfile, setSavingProfile] = useState(false);
  const [avatarLoadFailed, setAvatarLoadFailed] = useState(false);
  const [formState, setFormState] = useState({
    preferred_username: '',
    email: '',
    picture: '',
  });
  const callbackInFlightRef = useRef(false);

  function syncForm(nextProfile) {
    setFormState({
      preferred_username: String(nextProfile?.preferred_username || ''),
      email: String(nextProfile?.email || ''),
      picture: String(nextProfile?.picture || ''),
    });
  }

  async function saveProfile() {
    const saved = loadSession();
    const config = { ...defaultConfig(), ...(saved.config || {}) };
    const accessToken = saved.tokens?.access_token;
    if (!accessToken) {
      setStatus('Sessione non disponibile per il salvataggio.');
      return;
    }

    const payload = {
      preferred_username: String(formState.preferred_username || '').trim(),
      email: String(formState.email || '').trim(),
      picture: String(formState.picture || '').trim(),
    };

    setSavingProfile(true);
    try {
      const response = await fetch(issuerEndpoint(config.issuer, 'me'), {
        method: 'PATCH',
        headers: {
          authorization: `Bearer ${accessToken}`,
          'content-type': 'application/json',
        },
        body: JSON.stringify(payload),
      });

      if (!response.ok) {
        const body = await response.json().catch(() => ({}));
        throw new Error(body.error_description || body.error || 'Update profile non disponibile su server.');
      }

      const updated = profileFromPayload(await response.json());
      setProfile(updated);
      syncForm(updated);
      setEditMode(false);
      setStatus('');
    } catch (error) {
      setEditMode(false);
      setStatus(error?.message || 'Impossibile aggiornare il profilo.');
    } finally {
      setSavingProfile(false);
    }
  }

  useEffect(() => {
    let active = true;

    async function syncSession() {
      try {
        const params = new URLSearchParams(window.location.search);

        if (params.get('state') === 'authWidget-session-cleared' && !params.get('code') && !params.get('error')) {
          cleanupCurrentUrl();
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
          if (callbackInFlightRef.current) {
            return;
          }
          callbackInFlightRef.current = true;
          // Strip query params immediately so repeated lifecycle events
          // do not re-run code exchange with the same one-time code.
          cleanupCurrentUrl();
          if (active) setStatus('');
          await exchangeCode(code, state);
          const me = await fetchProfile();
          if (!active) return;
          setProfile(me);
          syncForm(me);
          setStatus('');
          setBusy(false);
          callbackInFlightRef.current = false;
          return;
        }

        const me = await fetchProfile();
        if (!active) return;
        setProfile(me);
        syncForm(me);
        setStatus('');
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
          clearSession();
          setStatus('Sessione scaduta');
          setBusy(false);
          return;
        }
        setStatus('Errore sessione');
        setBusy(false);
        callbackInFlightRef.current = false;
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

  useEffect(() => {
    emitProfileEvent(profile);
  }, [profile]);

  useEffect(() => {
    setAvatarLoadFailed(false);
  }, [profile?.picture, profile?.avatar_url]);

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

  const avatarUrl = !avatarLoadFailed ? (profile?.picture || profile?.avatar_url || '') : '';
  const identityLabel = profile?.email || profile?.preferred_username || profile?.sub || status;
  const avatarLabel = profile ? (profile.preferred_username || profile.email || profile.sub || 'U') : 'U';
  const ctas = runtimeConfigRef.current.ctas || {};
  const canExpand = Boolean(ctas.expand);
  const canEdit = Boolean(profile && ctas.editProfile);

  return (
    <section style={styles.shell}>
      <div style={styles.panel}>
        <div style={styles.row}>
          <button
            type="button"
            style={canExpand ? styles.avatarButton : { ...styles.avatarButton, cursor: 'default' }}
            onClick={canExpand ? () => setExpanded((prev) => !prev) : undefined}
            aria-label={canExpand ? (expanded ? 'Collapse profile' : 'Expand profile') : 'Profile avatar'}
            title={canExpand ? (expanded ? 'Collapse profile' : 'Expand profile') : ''}
          >
            {avatarUrl ? (
              <img style={styles.avatar} src={avatarUrl} alt={avatarLabel} onError={() => setAvatarLoadFailed(true)} />
            ) : (
              <div style={{ ...styles.avatar, ...styles.avatarPlaceholder }} aria-hidden="true">{avatarLabel.slice(0, 1).toUpperCase()}</div>
            )}
          </button>
          <div style={styles.content}>
            <span style={{ ...styles.text, ...(profile ? null : styles.textMuted) }}>
              {identityLabel}
            </span>
            <div style={styles.ctaWrap}>
              {!profile && ctas.login ? (
                <button style={{ ...styles.button, ...styles.loginButton, ...(busy ? { opacity: 0.7, cursor: 'wait' } : null) }} onClick={handleLogin} disabled={busy}>Login</button>
              ) : null}
              {profile && ctas.logout ? (
                <button style={{ ...styles.button, ...styles.logoutButton, ...(busy ? { opacity: 0.7, cursor: 'wait' } : null) }} onClick={handleLogout} disabled={busy}>Logout</button>
              ) : null}
            </div>
          </div>
          {busy ? <span style={styles.pending}>...</span> : null}
        </div>
        {status ? <div style={styles.status}>{status}</div> : null}
        {expanded ? (
          <div style={styles.body}>
            {!profile ? (
              <div style={styles.kvRow}>Nessun profilo disponibile. Esegui il login.</div>
            ) : (
              <>
                {editMode ? (
                  <>
                    <div style={styles.kvRow}>
                      <span style={styles.kvLabel}>Username</span>
                      <input style={styles.input} value={formState.preferred_username} onChange={(e) => setFormState((prev) => ({ ...prev, preferred_username: e.target.value }))} />
                    </div>
                    <div style={styles.kvRow}>
                      <span style={styles.kvLabel}>Email</span>
                      <input style={styles.input} value={formState.email} onChange={(e) => setFormState((prev) => ({ ...prev, email: e.target.value }))} />
                    </div>
                    <div style={styles.kvRow}>
                      <span style={styles.kvLabel}>Picture URL</span>
                      <input style={styles.input} value={formState.picture} onChange={(e) => setFormState((prev) => ({ ...prev, picture: e.target.value }))} />
                    </div>
                    <div style={styles.ctaWrap}>
                      <button style={styles.button} disabled={savingProfile} onClick={saveProfile}>Save</button>
                      <button
                        style={styles.button}
                        onClick={() => {
                          syncForm(profile);
                          setEditMode(false);
                        }}
                      >
                        Cancel
                      </button>
                    </div>
                  </>
                ) : (
                  <>
                    <div style={styles.kvRow}><span style={styles.kvLabel}>sub</span><span>{profile.sub || '-'}</span></div>
                    <div style={styles.kvRow}><span style={styles.kvLabel}>preferred_username</span><span>{profile.preferred_username || '-'}</span></div>
                    <div style={styles.kvRow}><span style={styles.kvLabel}>email</span><span>{profile.email || '-'}</span></div>
                    <div style={styles.kvRow}><span style={styles.kvLabel}>picture</span><span>{profile.picture || '-'}</span></div>
                    {canEdit ? (
                      <div style={styles.ctaWrap}>
                        <button style={styles.button} onClick={() => setEditMode(true)}>Edit profile</button>
                      </div>
                    ) : null}
                  </>
                )}
              </>
            )}
          </div>
        ) : null}
      </div>
    </section>
  );
}

export default function AuthWidgetApp() {
  return <OAuthProfileCard />;
}
