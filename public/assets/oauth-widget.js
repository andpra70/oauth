(function initOAuthWidget(global) {
  const React = global.React;
  const ReactDOM = global.ReactDOM;

  if (!React || !ReactDOM) {
    throw new Error('OAuthWidget requires global React and ReactDOM');
  }

  const appConfig = global.__APP_CONFIG__ || {};
  const baseUrl = new URL(appConfig.baseHref || global.location.href, global.location.origin);
  const mountedRoots = new Map();

  function appPath(path) {
    return new URL(String(path || '').replace(/^\/+/, ''), baseUrl).pathname;
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

  function resolveBrowserUrl(value) {
    const raw = String(value || '').trim();
    if (!raw) return '';
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(raw)) return raw;
    if (raw.startsWith('/')) return new URL(raw, global.location.origin).toString();
    return new URL(raw, baseUrl).toString();
  }

  function issuerEndpoint(issuer, path) {
    return new URL(String(path).replace(/^\/+/, ''), `${String(issuer || '').replace(/\/+$/, '')}/`).toString();
  }

  function normalizeOptions(options) {
    const redirectUri = options.redirectUri || `${global.location.origin}${global.location.pathname}`;

    return {
      clientId: options.clientId || 'fileserver-web',
      eventName: options.eventName || 'oauth-widget:profile',
      eventTarget: options.eventTarget || global,
      issuer: options.issuer || defaultIssuer(),
      onProfile: typeof options.onProfile === 'function' ? options.onProfile : null,
      position: options.position || { top: '16px', right: '16px' },
      postLogoutRedirectUri: options.postLogoutRedirectUri || redirectUri,
      redirectUri,
      scope: options.scope || 'openid profile email offline_access',
      storageKey: options.storageKey || 'oauth-widget',
      zIndex: options.zIndex || 2147483647,
    };
  }

  function loadSession(storageKey) {
    return JSON.parse(sessionStorage.getItem(storageKey) || '{}');
  }

  function saveSession(storageKey, data) {
    sessionStorage.setItem(storageKey, JSON.stringify(data));
  }

  function clearSession(storageKey) {
    sessionStorage.removeItem(storageKey);
  }

  async function exchangeCode(options, code, state) {
    const saved = loadSession(options.storageKey);
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
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body,
    });

    const payload = await response.json();
    if (!response.ok) {
      throw new Error(payload.error_description || payload.error || 'Token exchange fallito.');
    }

    saveSession(options.storageKey, { ...saved, tokens: payload });
    return payload;
  }

  async function fetchProfile(options) {
    const saved = loadSession(options.storageKey);
    const config = { ...options, ...(saved.config || {}) };
    const accessToken = saved.tokens?.access_token;
    if (!accessToken) {
      throw new Error('Access token non disponibile.');
    }

    const response = await fetch(issuerEndpoint(config.issuer, 'me'), {
      headers: { authorization: `Bearer ${accessToken}` },
    });

    const payload = await response.json();
    if (!response.ok) {
      throw new Error(payload.error_description || payload.error || 'UserInfo non disponibile.');
    }

    return payload;
  }

  async function startLoginFlow(options) {
    const config = {
      clientId: options.clientId,
      issuer: options.issuer,
      redirectUri: options.redirectUri,
      scope: options.scope,
    };
    const verifier = randomString(48);
    const state = randomString(24);
    const challenge = await sha256(verifier);

    saveSession(options.storageKey, { ...loadSession(options.storageKey), verifier, state, config });

    const url = new URL(issuerEndpoint(config.issuer, 'auth'));
    url.searchParams.set('client_id', config.clientId);
    url.searchParams.set('redirect_uri', resolveBrowserUrl(config.redirectUri));
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('scope', config.scope || 'openid');
    url.searchParams.set('code_challenge', challenge);
    url.searchParams.set('code_challenge_method', 'S256');
    url.searchParams.set('state', state);
    global.location.assign(url.toString());
  }

  function startLogoutFlow(options) {
    const saved = loadSession(options.storageKey);
    const config = { ...options, ...(saved.config || {}) };
    clearSession(options.storageKey);

    const url = new URL(issuerEndpoint(config.issuer, 'session/end'));
    url.searchParams.set('client_id', config.clientId || 'fileserver-web');
    url.searchParams.set('post_logout_redirect_uri', resolveBrowserUrl(config.postLogoutRedirectUri));
    url.searchParams.set('state', 'oauth-widget-session-cleared');
    global.location.assign(url.toString());
  }

  function emitProfile(options, profile) {
    const value = profile || null;
    options.eventTarget.dispatchEvent(new CustomEvent(options.eventName, {
      detail: { profile: value },
    }));
    if (options.onProfile) {
      options.onProfile(value);
    }
  }

  function createStyles(options) {
    return {
      shell: {
        position: 'fixed',
        top: options.position.top || '16px',
        right: options.position.right || '16px',
        left: options.position.left || 'auto',
        bottom: options.position.bottom || 'auto',
        zIndex: options.zIndex,
        pointerEvents: 'none',
      },
      panel: {
        pointerEvents: 'auto',
        display: 'inline-flex',
        alignItems: 'center',
        gap: '10px',
        minHeight: '46px',
        maxWidth: 'min(92vw, 360px)',
        padding: '8px 10px 8px 8px',
        border: '1px solid rgba(15, 23, 42, 0.12)',
        borderRadius: '999px',
        background: 'rgba(255, 255, 255, 0.96)',
        boxShadow: '0 10px 28px rgba(15, 23, 42, 0.16)',
        color: '#0f172a',
        fontFamily: 'ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
        whiteSpace: 'nowrap',
      },
      avatar: {
        width: '30px',
        height: '30px',
        borderRadius: '999px',
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
        borderRadius: '999px',
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
  }

  function OAuthWidgetComponent({ options }) {
    const [status, setStatus] = React.useState('Verifica sessione');
    const [profile, setProfile] = React.useState(null);
    const [busy, setBusy] = React.useState(true);
    const optionsRef = React.useRef(options);
    optionsRef.current = options;
    const styles = createStyles(options);

    React.useEffect(() => {
      let active = true;

      async function syncSession() {
        try {
          const params = new URLSearchParams(global.location.search);

          if (params.get('state') === 'oauth-widget-session-cleared' && !params.get('code') && !params.get('error')) {
            global.history.replaceState({}, global.document.title, new URL(optionsRef.current.redirectUri).pathname);
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
            await exchangeCode(optionsRef.current, code, state);
            if (active) {
              global.history.replaceState({}, global.document.title, new URL(optionsRef.current.redirectUri).pathname);
            }
            const me = await fetchProfile(optionsRef.current);
            if (!active) return;
            setProfile(me);
            setStatus('Utente autenticato. Profilo caricato da /me.');
            setBusy(false);
            return;
          }

          const me = await fetchProfile(optionsRef.current);
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

      global.addEventListener('pageshow', handlePageShow);
      global.addEventListener('popstate', handlePopState);

      return () => {
        active = false;
        global.removeEventListener('pageshow', handlePageShow);
        global.removeEventListener('popstate', handlePopState);
      };
    }, []);

    React.useEffect(() => {
      emitProfile(optionsRef.current, profile);
    }, [profile]);

    async function handleLogin() {
      setBusy(true);
      setStatus('Redirect login');
      await startLoginFlow(optionsRef.current);
    }

    function handleLogout() {
      setBusy(true);
      setStatus('Logout');
      startLogoutFlow(optionsRef.current);
    }

    const avatarUrl = profile?.picture || profile?.avatar_url || '';
    const identityLabel = profile?.email || profile?.preferred_username || profile?.sub || status;
    const avatarLabel = profile ? (profile.preferred_username || profile.email || profile.sub || 'U') : 'U';

    return React.createElement(
      'section',
      { style: styles.shell },
      React.createElement(
        'div',
        { style: styles.panel },
        avatarUrl
          ? React.createElement('img', { style: styles.avatar, src: avatarUrl, alt: avatarLabel })
          : React.createElement('div', { style: { ...styles.avatar, ...styles.avatarPlaceholder }, 'aria-hidden': 'true' }, avatarLabel.slice(0, 1).toUpperCase()),
        React.createElement(
          'div',
          { style: styles.content },
          React.createElement(
            'span',
            { style: { ...styles.text, ...(profile ? null : styles.textMuted) } },
            identityLabel,
          ),
          profile
            ? React.createElement(
              'button',
              {
                style: { ...styles.button, ...styles.logoutButton, ...(busy ? { opacity: 0.7, cursor: 'wait' } : null) },
                onClick: handleLogout,
                disabled: busy,
                type: 'button',
              },
              'Logout',
            )
            : React.createElement(
              'button',
              {
                style: { ...styles.button, ...styles.loginButton, ...(busy ? { opacity: 0.7, cursor: 'wait' } : null) },
                onClick: handleLogin,
                disabled: busy,
                type: 'button',
              },
              'Login',
            ),
        ),
        busy ? React.createElement('span', { style: styles.pending }, '...') : null,
      ),
    );
  }

  function mount(options) {
    const normalized = normalizeOptions(options || {});
    let target = normalized.target || global.document.body;
    let owned = false;

    if (!normalized.target) {
      target = global.document.createElement('div');
      target.dataset.oauthWidgetRoot = 'true';
      global.document.body.appendChild(target);
      owned = true;
    }

    if (mountedRoots.has(target)) {
      mountedRoots.get(target).root.unmount();
      if (mountedRoots.get(target).owned && target.isConnected) {
        target.remove();
      }
    }

    const root = ReactDOM.createRoot(target);
    root.render(React.createElement(OAuthWidgetComponent, { options: normalized }));
    mountedRoots.set(target, { owned, root });
    return target;
  }

  function unmount(target) {
    const entry = mountedRoots.get(target);
    if (!entry) return;
    entry.root.unmount();
    mountedRoots.delete(target);
    if (entry.owned && target.isConnected) {
      target.remove();
    }
  }

  global.OAuthWidget = {
    mount,
    unmount,
  };
}(window));
