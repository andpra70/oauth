import { useMemo } from 'react';
import AdminFooterMenu from './AdminFooterMenu.jsx';

export default function OidcSessionsAdminView({ payload, resolvePath }) {
  const {
    basePath = '',
    setupToken = '',
    store = {},
    notice = '',
    error = '',
  } = payload || {};

  const tokenQuery = useMemo(() => `?token=${encodeURIComponent(setupToken)}`, [setupToken]);
  const sessions = Array.isArray(store.sessions) ? store.sessions : [];
  const grants = Array.isArray(store.grants) ? store.grants : [];
  const recordsByModel = store.recordsByModel && typeof store.recordsByModel === 'object' ? store.recordsByModel : {};

  function toIso(ts) {
    const value = Number(ts || 0);
    if (!value) return '-';
    return new Date(value).toISOString();
  }

  function toIsoFromSeconds(ts) {
    const value = Number(ts || 0);
    if (!value) return '-';
    return new Date(value * 1000).toISOString();
  }

  return (
    <main className="admin-main">
      <section className="panel topbar">
        <div>
          <h1>OIDC sessions</h1>
          <p className="muted">Inspect active OIDC sessions, linked grants and token artifacts.</p>
        </div>
        <div className="actions">
          <a className="button-link secondary" href={resolvePath(basePath, `/setup/oidc-sessions${tokenQuery}`)}>Refresh</a>
        </div>
      </section>
      <AdminFooterMenu
        basePath={basePath}
        setupToken={setupToken}
        resolvePath={resolvePath}
        active="sessions"
      />

      {notice ? <section className="panel"><div className="message">{notice}</div></section> : null}
      {error ? <section className="panel"><div className="message error">{error}</div></section> : null}

      <section className="shell">
        <aside className="panel">
          <h2>Store summary</h2>
          <p className="muted">Generated at: {store.generatedAt || '-'}</p>
          <div className="meta">
            <div><strong>Sessions:</strong> {Number(store?.totals?.sessions || 0)}</div>
            <div><strong>Grants:</strong> {Number(store?.totals?.grants || 0)}</div>
          </div>
          <h3 style={{ marginTop: '14px' }}>Models</h3>
          <div className="list">
            {Object.keys(recordsByModel).length === 0 ? (
              <p className="muted">No records.</p>
            ) : Object.entries(recordsByModel).map(([model, count]) => (
              <div key={model} className="user-link">
                <strong>{model}</strong>
                <span>{Number(count || 0)} records</span>
              </div>
            ))}
          </div>
        </aside>

        <section className="panel">
          <h2>Active sessions</h2>
          {sessions.length === 0 ? <p className="muted">No active sessions.</p> : (
            <div className="list">
              {sessions.map((session) => (
                <article key={session.uid || session.id} className="user-link">
                  <strong>{session.uid || session.id}</strong>
                  <span>account: {session.accountId || '-'}</span>
                  <span>clients: {(session.clients || []).join(', ') || '-'}</span>
                  <span>login: {toIsoFromSeconds(session.loginTs)}</span>
                  <span>expires: {toIso(session.expiresAt)}</span>
                  <span>tokens: access {session.accessTokenCount || 0}, refresh {session.refreshTokenCount || 0}, code {session.authorizationCodeCount || 0}</span>
                  <form method="post" action={resolvePath(basePath, `/setup/oidc-sessions/session/${encodeURIComponent(session.uid || '')}/revoke${tokenQuery}`)}>
                    <button className="secondary" type="submit">Revoke session</button>
                  </form>
                </article>
              ))}
            </div>
          )}

          <h2 style={{ marginTop: '20px' }}>Grants</h2>
          {grants.length === 0 ? <p className="muted">No active grants.</p> : (
            <div className="list">
              {grants.map((grant) => (
                <article key={grant.id} className="user-link">
                  <strong>{grant.id}</strong>
                  <span>account: {grant.accountId || '-'}</span>
                  <span>client: {grant.clientId || '-'}</span>
                  <span>linked artifacts: {grant.linkedArtifacts || 0}</span>
                  <span>expires: {toIso(grant.expiresAt)}</span>
                  <form method="post" action={resolvePath(basePath, `/setup/oidc-sessions/grant/${encodeURIComponent(grant.id)}/revoke${tokenQuery}`)}>
                    <button className="secondary" type="submit">Revoke grant</button>
                  </form>
                </article>
              ))}
            </div>
          )}
        </section>
      </section>
    </main>
  );
}
