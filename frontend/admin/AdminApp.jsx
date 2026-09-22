import { useMemo, useState } from 'react';
import { createAdminApi } from './admin-api.js';
import { readAdminConfig } from './admin-model.js';
import { AdminLayout } from './components/AdminLayout.jsx';
import { UsersPage } from './components/UsersPage.jsx';
import { ClientsPage } from './components/ClientsPage.jsx';
import { SessionsPage } from './components/SessionsPage.jsx';
import { RuntimePage } from './components/RuntimePage.jsx';

export function AdminApp() {
  const [{ basePath, token, page: initialPage }] = useState(readAdminConfig); const [page, setPage] = useState(initialPage); const [error, setError] = useState(''); const [notice, setNotice] = useState('');
  const api = useMemo(() => createAdminApi(basePath, token), [basePath, token]);
  const report = useMemo(() => ({ error: (reason) => { setNotice(''); setError(reason?.message || String(reason)); }, notice: (message) => { setError(''); setNotice(message); }, clear: () => { setError(''); setNotice(''); } }), []);
  if (!token) return <main className="admin"><section className="panel auth"><h1>Accesso amministrativo</h1><p>Apri questa pagina una volta con <code>?token=SETUP_TOKEN</code>. Il token verrà conservato nella sessione del browser e rimosso dall’indirizzo.</p></section></main>;
  const content = { users: <UsersPage api={api} report={report} />, clients: <ClientsPage api={api} report={report} />, sessions: <SessionsPage api={api} report={report} />, runtime: <RuntimePage api={api} report={report} /> }[page];
  return <AdminLayout page={page} onPage={(value) => { setPage(value); report.clear(); }} error={error} notice={notice}>{content}</AdminLayout>;
}
