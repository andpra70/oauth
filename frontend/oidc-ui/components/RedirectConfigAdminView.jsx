import { useMemo } from 'react';
import AdminFooterMenu from './AdminFooterMenu.jsx';

export default function RedirectConfigAdminView({ payload, resolvePath }) {
  const {
    basePath = '',
    setupToken = '',
    clients = [],
    selectedClientId = '',
    selectedClient = null,
    values = {},
    createValues = {},
    notice = '',
    error = '',
  } = payload || {};

  const tokenQuery = useMemo(() => `?token=${encodeURIComponent(setupToken)}`, [setupToken]);

  return (
    <main className="admin-main">
      <section className="panel topbar">
        <div>
          <h1>Redirect URI configuration</h1>
          <p className="muted">Gestisci le URI valide per login e logout OIDC dei client registrati.</p>
        </div>
      </section>
      <AdminFooterMenu
        basePath={basePath}
        setupToken={setupToken}
        resolvePath={resolvePath}
        active="config"
      />

      {notice ? <section className="panel"><div className="message">{notice}</div></section> : null}
      {error ? <section className="panel"><div className="message error">{error}</div></section> : null}

      <section className="panel">
        {clients.length === 0 ? (
          <p className="muted">Nessun client configurato.</p>
        ) : (
          <>
            <form method="get" action={resolvePath(basePath, '/setup/config')}>
              <input type="hidden" name="token" value={setupToken} />
              <div className="form-grid">
                <div className="field full">
                  <label>Client selezionato</label>
                  <select name="client_id" defaultValue={selectedClientId}>
                    {clients.map((client) => (
                      <option key={client.client_id} value={client.client_id}>{client.client_id}</option>
                    ))}
                  </select>
                </div>
              </div>
              <div className="actions">
                <button type="submit">Apri client</button>
              </div>
            </form>
            <form method="post" action={resolvePath(basePath, `/setup/config${tokenQuery}`)}>
              <div className="form-grid">
                <div className="field full">
                  <label>Client</label>
                  <select name="client_id" defaultValue={selectedClientId}>
                    {clients.map((client) => (
                      <option key={client.client_id} value={client.client_id}>{client.client_id}</option>
                    ))}
                  </select>
                </div>
                <div className="field full">
                  <label>redirect_uris (una per riga)</label>
                  <textarea name="redirect_uris" rows={10} defaultValue={String(values.redirect_uris || '')} />
                </div>
                <div className="field full">
                  <label>post_logout_redirect_uris (una per riga)</label>
                  <textarea name="post_logout_redirect_uris" rows={8} defaultValue={String(values.post_logout_redirect_uris || '')} />
                </div>
              </div>
              <div className="actions">
                <button type="submit">Salva configurazione</button>
                <a className="button-link secondary" href={resolvePath(basePath, `/setup/config${tokenQuery}`)}>Ricarica</a>
              </div>
            </form>
          </>
        )}
      </section>

      <section className="panel">
        <h2 style={{ marginTop: 0 }}>Client lifecycle</h2>
        <p className="muted">Crea un nuovo client o elimina quello selezionato.</p>
        <form method="post" action={resolvePath(basePath, `/setup/config/client/create${tokenQuery}`)}>
          <div className="form-grid">
            <div className="field">
              <label>client_id</label>
              <input name="client_id" required defaultValue={String(createValues.client_id || '')} />
            </div>
            <div className="field">
              <label>token_endpoint_auth_method</label>
              <select name="token_endpoint_auth_method" defaultValue={String(createValues.token_endpoint_auth_method || 'none')}>
                <option value="none">none</option>
                <option value="client_secret_post">client_secret_post</option>
                <option value="client_secret_basic">client_secret_basic</option>
              </select>
            </div>
            <div className="field full">
              <label>client_secret (richiesto se auth method != none, min 24 chars)</label>
              <input name="client_secret" defaultValue={String(createValues.client_secret || '')} />
            </div>
            <div className="field full">
              <label>scope</label>
              <input name="scope" defaultValue={String(createValues.scope || 'openid profile email offline_access')} />
            </div>
            <div className="field">
              <label>grant_types (una per riga)</label>
              <textarea name="grant_types" rows={4} defaultValue={String(createValues.grant_types || 'authorization_code\nrefresh_token')} />
            </div>
            <div className="field">
              <label>response_types (una per riga)</label>
              <textarea name="response_types" rows={4} defaultValue={String(createValues.response_types || 'code')} />
            </div>
            <div className="field full">
              <label>redirect_uris (una per riga)</label>
              <textarea name="redirect_uris" rows={6} defaultValue={String(createValues.redirect_uris || '')} />
            </div>
            <div className="field full">
              <label>post_logout_redirect_uris (una per riga)</label>
              <textarea name="post_logout_redirect_uris" rows={4} defaultValue={String(createValues.post_logout_redirect_uris || '')} />
            </div>
          </div>
          <div className="actions">
            <button type="submit">Crea client</button>
          </div>
        </form>
        {selectedClient?.client_id ? (
          <form
            method="post"
            action={resolvePath(basePath, `/setup/config/client/${encodeURIComponent(selectedClient.client_id)}/delete${tokenQuery}`)}
            onSubmit={(event) => {
              if (!window.confirm(`Eliminare client ${selectedClient.client_id}?`)) event.preventDefault();
            }}
          >
            <button className="secondary danger" type="submit">Elimina client selezionato ({selectedClient.client_id})</button>
          </form>
        ) : null}
      </section>

    </main>
  );
}
