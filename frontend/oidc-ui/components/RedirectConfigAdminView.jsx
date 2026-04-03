import { useEffect, useMemo, useRef, useState } from 'react';
import AdminFooterMenu from './AdminFooterMenu.jsx';

export default function RedirectConfigAdminView({ payload, resolvePath }) {
  const {
    basePath = '',
    setupToken = '',
    clients = [],
    isNew = false,
    selectedClientId = '',
    selectedClient = null,
    values = {},
    createValues = {},
    notice = '',
    error = '',
  } = payload || {};

  const tokenQuery = useMemo(() => `?token=${encodeURIComponent(setupToken)}`, [setupToken]);
  const editorFormRef = useRef(null);
  const [localError, setLocalError] = useState('');
  const [tokenTestBusy, setTokenTestBusy] = useState(false);
  const [tokenTestResult, setTokenTestResult] = useState('');
  const [tokenTestAccessToken, setTokenTestAccessToken] = useState('');
  const [meTestBusy, setMeTestBusy] = useState(false);
  const [meTestResult, setMeTestResult] = useState('');
  const [testAuthCode, setTestAuthCode] = useState('');
  const [testRedirectUri, setTestRedirectUri] = useState('');
  const [testCodeVerifier, setTestCodeVerifier] = useState('');
  const current = isNew ? null : selectedClient;
  const workingValues = isNew ? createValues : values;
  const clientKind = String(workingValues.client_kind || 'browser');
  const tokenEndpointAuthMethod = String(workingValues.token_endpoint_auth_method || (clientKind === 'application' ? 'client_secret_post' : 'none'));
  const isApplication = clientKind === 'application';
  const canEdit = isNew || Boolean(current?.client_id);
  const formAction = isNew
    ? resolvePath(basePath, `/setup/config/client/create${tokenQuery}`)
    : resolvePath(basePath, `/setup/config/client/${encodeURIComponent(current?.client_id || '')}/update${tokenQuery}`);
  const tokenEndpoint = resolvePath(basePath, '/token');
  const meEndpoint = resolvePath(basePath, '/me');
  const introspectionEndpoint = resolvePath(basePath, '/token/introspection');
  const tokenEndpointAbsolute = typeof window !== 'undefined'
    ? `${window.location.origin}${tokenEndpoint}`
    : tokenEndpoint;
  const introspectionEndpointAbsolute = typeof window !== 'undefined'
    ? `${window.location.origin}${introspectionEndpoint}`
    : introspectionEndpoint;
  const exampleClientId = String(workingValues.client_id || current?.client_id || '');
  const exampleClientSecret = String(workingValues.api_key || workingValues.client_secret || '');
  const exampleIntrospectionToken = tokenTestAccessToken || '<ACCESS_TOKEN>';
  const rawExampleScope = String(workingValues.scope || 'openid profile email offline_access');
  const exampleScope = rawExampleScope
    .split(/\s+/g)
    .map((item) => item.trim())
    .filter(Boolean)
    .filter((item) => item !== 'openid' && item !== 'offline_access')
    .join(' ');
  const curlClientSecretPost = [
    `curl -X POST "${tokenEndpointAbsolute}"`,
    `  -H "content-type: application/x-www-form-urlencoded"`,
    `  --data-urlencode "grant_type=client_credentials"`,
    `  --data-urlencode "client_id=${exampleClientId}"`,
    `  --data-urlencode "client_secret=${exampleClientSecret}"`,
    ...(exampleScope ? [`  --data-urlencode "scope=${exampleScope}"`] : []),
  ].join('\n');
  const curlClientSecretBasic = [
    `curl -X POST "${tokenEndpointAbsolute}"`,
    `  -u "${exampleClientId}:${exampleClientSecret}"`,
    `  -H "content-type: application/x-www-form-urlencoded"`,
    `  --data-urlencode "grant_type=client_credentials"`,
    ...(exampleScope ? [`  --data-urlencode "scope=${exampleScope}"`] : []),
  ].join('\n');
  const curlIntrospectionPost = [
    `curl -X POST "${introspectionEndpointAbsolute}"`,
    `  -H "content-type: application/x-www-form-urlencoded"`,
    `  --data-urlencode "token=${exampleIntrospectionToken}"`,
    `  --data-urlencode "token_type_hint=access_token"`,
    `  --data-urlencode "client_id=${exampleClientId}"`,
    `  --data-urlencode "client_secret=${exampleClientSecret}"`,
  ].join('\n');
  const curlIntrospectionBasic = [
    `curl -X POST "${introspectionEndpointAbsolute}"`,
    `  -u "${exampleClientId}:${exampleClientSecret}"`,
    `  -H "content-type: application/x-www-form-urlencoded"`,
    `  --data-urlencode "token=${exampleIntrospectionToken}"`,
    `  --data-urlencode "token_type_hint=access_token"`,
  ].join('\n');

  function parseLines(value) {
    return String(value || '')
      .split(/\r?\n|,/g)
      .map((item) => item.trim())
      .filter(Boolean);
  }

  function defaultRedirectUriForTest() {
    const list = parseLines(workingValues.redirect_uris || '');
    return list[0] || '';
  }

  function validateForm(form) {
    const data = new FormData(form);
    const clientId = String(data.get('client_id') || '').trim();
    const clientKindValue = String(data.get('client_kind') || '').trim();
    const authMethodValue = String(data.get('token_endpoint_auth_method') || '').trim();
    const clientSecretValue = String(data.get('client_secret') || '').trim();
    const apiKeyValue = String(data.get('api_key') || '').trim();
    const grantTypes = parseLines(data.get('grant_types'));
    const redirectUris = parseLines(data.get('redirect_uris'));
    const postLogoutRedirectUris = parseLines(data.get('post_logout_redirect_uris'));

    if (!clientId) return 'client_id obbligatorio.';
    if (clientKindValue === 'application' && authMethodValue === 'none') {
      return 'I client application richiedono token_endpoint_auth_method diverso da none.';
    }
    if (authMethodValue !== 'none') {
      const secret = clientKindValue === 'application'
        ? (apiKeyValue || clientSecretValue)
        : clientSecretValue;
      if (!secret || secret.length < 24) {
        return 'client_secret/api_key deve essere lunga almeno 24 caratteri.';
      }
    }

    for (const uri of redirectUris) {
      try {
        new URL(uri);
      } catch {
        return `redirect_uri non valida: ${uri}`;
      }
    }
    for (const uri of postLogoutRedirectUris) {
      try {
        new URL(uri);
      } catch {
        return `post_logout_redirect_uri non valida: ${uri}`;
      }
    }

    if (grantTypes.includes('authorization_code') && redirectUris.length === 0) {
      return 'Con grant_type authorization_code serve almeno una redirect_uri.';
    }

    return '';
  }

  function handleFormSubmit(event) {
    const message = validateForm(event.currentTarget);
    if (message) {
      event.preventDefault();
      setLocalError(message);
      return;
    }
    setLocalError('');
  }

  function handleFormInput(event) {
    if (!localError) return;
    const form = event.currentTarget.form || event.currentTarget.closest('form');
    if (!form) return;
    const message = validateForm(form);
    setLocalError(message);
  }

  async function runBrowserTokenTest(event) {
    const form = editorFormRef.current;
    if (!form) {
      setTokenTestResult(JSON.stringify({
        ok: false,
        error: 'Form client non disponibile',
      }, null, 2));
      return;
    }

    const message = validateForm(form);
    if (message) {
      setLocalError(message);
      return;
    }

    const data = new FormData(form);
    const clientId = String(data.get('client_id') || '').trim();
    const clientKindValue = String(data.get('client_kind') || '').trim();
    const authMethodValue = String(data.get('token_endpoint_auth_method') || '').trim();
    const clientSecretValue = String(data.get('client_secret') || '').trim();
    const apiKeyValue = String(data.get('api_key') || '').trim();
    const scopeValue = String(data.get('scope') || '').trim() || 'openid profile email offline_access';
    const normalizedScope = scopeValue
      .split(/\s+/g)
      .map((item) => item.trim())
      .filter(Boolean)
      .filter((item) => item !== 'openid' && item !== 'offline_access')
      .join(' ');
    const secret = clientKindValue === 'application'
      ? (apiKeyValue || clientSecretValue)
      : clientSecretValue;

    const body = new URLSearchParams();
    const headers = {
      'content-type': 'application/x-www-form-urlencoded',
    };

    if (clientKindValue === 'application') {
      body.set('grant_type', 'client_credentials');
      if (normalizedScope) body.set('scope', normalizedScope);
      if (authMethodValue === 'client_secret_basic') {
        headers.authorization = `Basic ${btoa(`${clientId}:${secret}`)}`;
      } else {
        body.set('client_id', clientId);
        body.set('client_secret', secret);
      }
    } else {
      const code = String(testAuthCode || '').trim();
      const redirectUri = String(testRedirectUri || '').trim();
      const codeVerifier = String(testCodeVerifier || '').trim();
      if (!code) {
        setLocalError('Per client utente inserisci authorization code per test token.');
        return;
      }
      if (!redirectUri) {
        setLocalError('Per client utente inserisci redirect_uri per test token.');
        return;
      }
      body.set('grant_type', 'authorization_code');
      body.set('client_id', clientId);
      body.set('code', code);
      body.set('redirect_uri', redirectUri);
      if (codeVerifier) body.set('code_verifier', codeVerifier);
      if (authMethodValue === 'client_secret_basic') {
        headers.authorization = `Basic ${btoa(`${clientId}:${secret}`)}`;
      } else if (authMethodValue !== 'none') {
        body.set('client_secret', secret);
      }
    }

    setTokenTestBusy(true);
    setTokenTestResult('Esecuzione test token in corso...');
    setTokenTestAccessToken('');
    setMeTestResult('');
    try {
      const response = await fetch(tokenEndpoint, {
        method: 'POST',
        headers,
        body,
      });
      const text = await response.text();
      let parsed;
      try {
        parsed = JSON.parse(text);
      } catch {
        parsed = { raw: text };
      }
      const payload = {
        ok: response.ok,
        status: response.status,
        data: parsed,
      };
      const nextAccessToken = typeof parsed?.access_token === 'string' ? parsed.access_token : '';
      setTokenTestAccessToken(nextAccessToken);
      setTokenTestResult(JSON.stringify(payload, null, 2));
    } catch (err) {
      setTokenTestAccessToken('');
      setTokenTestResult(JSON.stringify({
        ok: false,
        error: err?.message || 'Errore chiamata token endpoint',
      }, null, 2));
    } finally {
      setTokenTestBusy(false);
    }
  }

  async function runMeTest() {
    if (!tokenTestAccessToken) {
      setMeTestResult(JSON.stringify({
        ok: false,
        error: 'Access token non disponibile. Esegui prima il test token.',
      }, null, 2));
      return;
    }

    const form = editorFormRef.current;
    if (!form) {
      setMeTestResult(JSON.stringify({
        ok: false,
        error: 'Form client non disponibile',
      }, null, 2));
      return;
    }

    const data = new FormData(form);
    const currentClientKind = String(data.get('client_kind') || '').trim();
    if (currentClientKind === 'application') {
      setMeTestResult(JSON.stringify({
        ok: false,
        status: 401,
        error: '/me richiede un token utente (authorization_code/login).',
        hint: 'Per i token client_credentials usa "Test introspection token".',
      }, null, 2));
      return;
    }

    setMeTestBusy(true);
    setMeTestResult('Chiamata /me in corso...');
    try {
      const response = await fetch(meEndpoint, {
        method: 'GET',
        headers: {
          authorization: `Bearer ${tokenTestAccessToken}`,
        },
      });
      const text = await response.text();
      let parsed;
      try {
        parsed = JSON.parse(text);
      } catch {
        parsed = { raw: text };
      }
      setMeTestResult(JSON.stringify({
        ok: response.ok,
        status: response.status,
        data: parsed,
      }, null, 2));
    } catch (err) {
      setMeTestResult(JSON.stringify({
        ok: false,
        error: err?.message || 'Errore chiamata /me',
      }, null, 2));
    } finally {
      setMeTestBusy(false);
    }
  }

  async function runIntrospectionTest() {
    if (!tokenTestAccessToken) {
      setMeTestResult(JSON.stringify({
        ok: false,
        error: 'Access token non disponibile. Esegui prima il test token.',
      }, null, 2));
      return;
    }

    const form = editorFormRef.current;
    if (!form) {
      setMeTestResult(JSON.stringify({
        ok: false,
        error: 'Form client non disponibile',
      }, null, 2));
      return;
    }

    const data = new FormData(form);
    const clientId = String(data.get('client_id') || '').trim();
    const clientSecretValue = String(data.get('client_secret') || '').trim();
    const apiKeyValue = String(data.get('api_key') || '').trim();
    const authMethodValue = String(data.get('token_endpoint_auth_method') || '').trim();
    const clientKindValue = String(data.get('client_kind') || '').trim();
    const secret = clientKindValue === 'application'
      ? (apiKeyValue || clientSecretValue)
      : clientSecretValue;

    const body = new URLSearchParams();
    body.set('token', tokenTestAccessToken);
    body.set('token_type_hint', 'access_token');
    if (authMethodValue !== 'client_secret_basic') {
      body.set('client_id', clientId);
      body.set('client_secret', secret);
    }

    const headers = {
      'content-type': 'application/x-www-form-urlencoded',
    };
    if (authMethodValue === 'client_secret_basic') {
      headers.authorization = `Basic ${btoa(`${clientId}:${secret}`)}`;
    }

    setMeTestBusy(true);
    setMeTestResult('Chiamata introspection in corso...');
    try {
      const response = await fetch(introspectionEndpoint, {
        method: 'POST',
        headers,
        body,
      });
      const text = await response.text();
      let parsed;
      try {
        parsed = JSON.parse(text);
      } catch {
        parsed = { raw: text };
      }
      setMeTestResult(JSON.stringify({
        ok: response.ok,
        status: response.status,
        data: parsed,
      }, null, 2));
    } catch (err) {
      setMeTestResult(JSON.stringify({
        ok: false,
        error: err?.message || 'Errore chiamata introspection',
      }, null, 2));
    } finally {
      setMeTestBusy(false);
    }
  }

  useEffect(() => {
    setLocalError('');
    setTokenTestResult('');
    setTokenTestAccessToken('');
    setMeTestResult('');
    setTestAuthCode('');
    setTestCodeVerifier('');
    setTestRedirectUri(defaultRedirectUriForTest());
  }, [isNew, selectedClientId]);

  return (
    <main className="admin-main">
      <section className="panel topbar">
        <div>
          <h1>Redirect URI configuration</h1>
          <p className="muted">Gestisci i client OIDC in modalità master-detail: lista a sinistra, configurazione completa a destra.</p>
        </div>
      </section>
      <AdminFooterMenu
        basePath={basePath}
        setupToken={setupToken}
        resolvePath={resolvePath}
        active="config"
      />

      <section className="shell">
        <aside className="panel">
          <div className="topbar">
            <h2 style={{ margin: 0 }}>Client</h2>
            <a className="button-link secondary" style={{ width: 'auto', marginTop: 0, paddingInline: '14px' }} href={resolvePath(basePath, `/setup/config?token=${encodeURIComponent(setupToken)}&new=1`)}>Nuovo client</a>
          </div>
          <p className="muted" style={{ marginTop: '6px' }}>{clients.length} totali</p>
          <div className="list">
            {clients.length === 0 ? (
              <p className="muted" style={{ marginTop: '12px' }}>Nessun client registrato.</p>
            ) : clients.map((client) => {
              const isActive = !isNew && selectedClientId === client.client_id;
              return (
                <a key={client.client_id} className={`user-link${isActive ? ' active' : ''}`} href={resolvePath(basePath, `/setup/config?token=${encodeURIComponent(setupToken)}&client_id=${encodeURIComponent(client.client_id)}`)}>
                  <strong>{client.client_id}</strong>
                  <span>{client.client_kind === 'application' ? 'application' : 'browser'} · {client.token_endpoint_auth_method || 'none'}</span>
                </a>
              );
            })}
          </div>
        </aside>
        <section className="panel">
          <h2>{isNew ? 'Nuovo client' : 'Dettaglio client'}</h2>
          {notice ? <div className="message">{notice}</div> : null}
          {error ? <div className="message error">{error}</div> : null}
          {localError ? <div className="message error">{localError}</div> : null}
          {!canEdit ? (
            <div className="message">Nessun client disponibile. Usa "Aggiungi client" per creare il primo client.</div>
          ) : (
            <form ref={editorFormRef} method="post" action={formAction} onSubmit={handleFormSubmit}>
              <div className="form-grid">
                <div className="field">
                  <label>client_id</label>
                  <input name="client_id" required defaultValue={String(workingValues.client_id || '')} readOnly={!isNew} onInput={handleFormInput} />
                </div>
                <div className="field">
                  <label>client_kind</label>
                  <select name="client_kind" defaultValue={clientKind} onInput={handleFormInput}>
                    <option value="browser">browser</option>
                    <option value="application">application</option>
                  </select>
                </div>
                <div className="field">
                  <label>token_endpoint_auth_method</label>
                  <select name="token_endpoint_auth_method" defaultValue={tokenEndpointAuthMethod} onInput={handleFormInput}>
                    <option value="none">none</option>
                    <option value="client_secret_post">client_secret_post</option>
                    <option value="client_secret_basic">client_secret_basic</option>
                  </select>
                </div>
                <div className="field">
                  <label>scope</label>
                  <input name="scope" defaultValue={String(workingValues.scope || 'openid profile email offline_access')} onInput={handleFormInput} />
                </div>
                <div className="field full">
                  <label>client_secret (min 24 chars se auth method != none)</label>
                  <input name="client_secret" defaultValue={String(workingValues.client_secret || '')} onInput={handleFormInput} />
                </div>
                <div className="field full">
                  <label>api_key applicativa (opzionale, min 24 chars; se vuota viene generata per client application)</label>
                  <input name="api_key" defaultValue={String(workingValues.api_key || '')} onInput={handleFormInput} />
                </div>
                <div className="field">
                  <label>grant_types (uno per riga)</label>
                  <textarea name="grant_types" rows={4} defaultValue={String(workingValues.grant_types || (isApplication ? 'client_credentials' : 'authorization_code\nrefresh_token'))} onInput={handleFormInput} />
                </div>
                <div className="field">
                  <label>response_types (uno per riga)</label>
                  <textarea name="response_types" rows={4} defaultValue={String(workingValues.response_types || (isApplication ? '' : 'code'))} onInput={handleFormInput} />
                </div>
                <div className="field full">
                  <label>redirect_uris (una per riga, richiesto se usi authorization_code)</label>
                  <textarea name="redirect_uris" rows={6} defaultValue={String(workingValues.redirect_uris || '')} onInput={handleFormInput} />
                </div>
                <div className="field full">
                  <label>post_logout_redirect_uris (una per riga)</label>
                  <textarea name="post_logout_redirect_uris" rows={4} defaultValue={String(workingValues.post_logout_redirect_uris || '')} onInput={handleFormInput} />
                </div>
              </div>
              <div className="actions">
                <button type="submit">{isNew ? 'Crea client' : 'Salva modifiche'}</button>
                <a className="button-link secondary" href={resolvePath(basePath, `/setup/config?token=${encodeURIComponent(setupToken)}&new=1`)}>Nuovo client</a>
                {!isNew && current?.client_id ? <a className="button-link secondary" href={resolvePath(basePath, `/setup/config?token=${encodeURIComponent(setupToken)}&client_id=${encodeURIComponent(current.client_id)}`)}>Ricarica</a> : null}
              </div>
            </form>
          )}
          {isApplication ? (
            <div className="meta">
              <div><strong>Token endpoint:</strong> {tokenEndpoint}</div>
              <div><strong>Esempio:</strong> grant_type=client_credentials con client auth (`client_secret_post` o `client_secret_basic`) usando `client_id` + `api_key`.</div>
              <div className="actions">
                <button className="secondary" type="button" onClick={runBrowserTokenTest} disabled={tokenTestBusy}>
                  {tokenTestBusy ? 'Test token in corso...' : 'Test token da browser'}
                </button>
                <button className="secondary" type="button" onClick={runIntrospectionTest} disabled={meTestBusy || !tokenTestAccessToken}>
                  {meTestBusy ? 'Introspection in corso...' : 'Test introspection token'}
                </button>
              </div>
              {tokenTestResult ? <pre>{tokenTestResult}</pre> : null}
              {meTestResult ? <pre>{meTestResult}</pre> : null}
              <div><strong>Test token (`client_secret_post`):</strong></div>
              <pre>{curlClientSecretPost}</pre>
              <div><strong>Test token (`client_secret_basic`):</strong></div>
              <pre>{curlClientSecretBasic}</pre>
              <div><strong>Introspection (`client_secret_post`):</strong></div>
              <pre>{curlIntrospectionPost}</pre>
              <div><strong>Introspection (`client_secret_basic`):</strong></div>
              <pre>{curlIntrospectionBasic}</pre>
            </div>
          ) : (
            <div className="meta">
              <div><strong>Token endpoint:</strong> {tokenEndpoint}</div>
              <div><strong>Test token client utente:</strong> usa `authorization_code` ottenuto dal flow login.</div>
              <div className="form-grid">
                <div className="field full">
                  <label>authorization_code</label>
                  <input value={testAuthCode} onChange={(event) => setTestAuthCode(event.target.value)} placeholder="Inserisci code ricevuto dal redirect" />
                </div>
                <div className="field full">
                  <label>redirect_uri</label>
                  <input value={testRedirectUri} onChange={(event) => setTestRedirectUri(event.target.value)} placeholder="https://app.example/callback" />
                </div>
                <div className="field full">
                  <label>code_verifier (PKCE, opzionale se non usato)</label>
                  <input value={testCodeVerifier} onChange={(event) => setTestCodeVerifier(event.target.value)} placeholder="code_verifier usato in authorize" />
                </div>
              </div>
              <div className="actions">
                <button className="secondary" type="button" onClick={runBrowserTokenTest} disabled={tokenTestBusy}>
                  {tokenTestBusy ? 'Test token in corso...' : 'Test token da browser'}
                </button>
                <button className="secondary" type="button" onClick={runMeTest} disabled={meTestBusy || !tokenTestAccessToken}>
                  {meTestBusy ? 'Test /me in corso...' : 'Test /me con token'}
                </button>
                <button className="secondary" type="button" onClick={runIntrospectionTest} disabled={meTestBusy || !tokenTestAccessToken}>
                  {meTestBusy ? 'Introspection in corso...' : 'Test introspection token'}
                </button>
              </div>
              {tokenTestResult ? <pre>{tokenTestResult}</pre> : null}
              {meTestResult ? <pre>{meTestResult}</pre> : null}
            </div>
          )}
          {!isNew && current?.client_id ? (
            <form
              method="post"
              action={resolvePath(basePath, `/setup/config/client/${encodeURIComponent(current.client_id)}/delete${tokenQuery}`)}
              onSubmit={(event) => {
                if (!window.confirm(`Eliminare client ${current.client_id}?`)) event.preventDefault();
              }}
            >
              <button className="secondary danger" type="submit">Elimina client ({current.client_id})</button>
            </form>
          ) : null}
        </section>
      </section>

    </main>
  );
}
