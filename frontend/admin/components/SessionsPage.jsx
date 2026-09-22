import { useEffect, useState } from 'react';
export function SessionsPage({ api, report }) {
  const [store, setStore] = useState({}); const load = async () => setStore((await api.sessions()).store);
  useEffect(() => { load().catch(report.error); }, []);
  const revoke = async (type, id) => { if (!confirm(`Revocare ${id}?`)) return; try { await ({ session: api.revokeSession, grant: api.revokeGrant, token: api.revokeClientToken }[type])(id); await load(); report.notice('Revoca completata'); } catch (error) { report.error(error); } };
  const group = (title, items, type, idKey = 'id') => <section className="panel"><h2>{title}</h2>{!items?.length ? <p>Nessun elemento.</p> : items.map((item) => { const id = item[idKey] || item.id; return <article className="record" key={id}><div><strong>{id}</strong><small>{item.accountId || item.clientId || ''}</small></div><button className="danger" onClick={() => revoke(type, id)}>Revoca</button></article>; })}</section>;
  return <div className="stack">{group('Sessioni', store.sessions, 'session', 'uid')}{group('Grant', store.grants, 'grant')}{group('Token client credentials', store.clientCredentialsTokens, 'token')}</div>;
}
