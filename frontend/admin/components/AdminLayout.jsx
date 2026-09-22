const ITEMS = [['users', 'Utenti'], ['clients', 'Client OIDC'], ['sessions', 'Sessioni'], ['runtime', 'Configurazione']];
export function AdminLayout({ page, onPage, error, notice, children }) {
  return <main className="admin"><header><div><h1>Gestione OAuth</h1><p>Amministrazione utenti, client, sessioni e funzionalità.</p></div></header><nav>{ITEMS.map(([id, label]) => <button key={id} className={page === id ? 'active' : ''} onClick={() => onPage(id)}>{label}</button>)}</nav>{error && <p className="message error">{error}</p>}{notice && <p className="message notice">{notice}</p>}{children}</main>;
}
