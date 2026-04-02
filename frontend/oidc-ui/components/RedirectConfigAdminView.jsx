import { useMemo } from 'react';
import AdminFooterMenu from './AdminFooterMenu.jsx';

export default function RedirectConfigAdminView({ payload, resolvePath }) {
  const {
    basePath = '',
    setupToken = '',
    clients = [],
    selectedClientId = '',
    values = {},
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

    </main>
  );
}
