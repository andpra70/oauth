import { useMemo } from 'react';

export default function UsersAdminView({ payload, resolvePath }) {
  const {
    basePath = '',
    setupToken = '',
    users = [],
    selectedUser = null,
    formValues = {},
    error = '',
    notice = '',
    isNew = false,
  } = payload || {};

  const tokenQuery = useMemo(() => `?token=${encodeURIComponent(setupToken)}`, [setupToken]);
  const current = selectedUser || null;
  const values = {
    username: formValues.username ?? current?.username ?? '',
    email: formValues.email ?? current?.email ?? '',
    auth_provider: formValues.auth_provider ?? current?.auth_provider ?? 'local',
    picture: formValues.picture ?? current?.picture ?? '',
    google_subject: formValues.google_subject ?? current?.google_subject ?? '',
    totp_enabled: String(formValues.totp_enabled ?? current?.totp_enabled ?? '0') === '1' ? '1' : '0',
  };
  const formAction = isNew
    ? resolvePath(basePath, `/setup/users${tokenQuery}`)
    : resolvePath(basePath, `/setup/users/${encodeURIComponent(current?.id || '')}${tokenQuery}`);

  return (
    <main className="admin-main">
      <section className="panel topbar">
        <div>
          <h1>User management</h1>
          <p className="muted">Create, inspect, edit and delete users stored in the JSON database.</p>
        </div>
        <div className="actions">
          <a className="button-link secondary" href={resolvePath(basePath, `/setup/users/new${tokenQuery}`)}>Add user</a>
          <a className="button-link secondary" href={resolvePath(basePath, '/app')}>Back to app</a>
        </div>
      </section>
      <section className="shell">
        <aside className="panel">
          <h2>Users</h2>
          <p className="muted" style={{ marginTop: '6px' }}>{users.length} total</p>
          <div className="list">
            {users.length === 0 ? <p className="muted" style={{ marginTop: '12px' }}>No users found.</p> : users.map((user) => {
              const isActive = current?.id === user.id && !isNew;
              const label = user.email || user.username || user.id;
              return (
                <a key={user.id} className={`user-link${isActive ? ' active' : ''}`} href={resolvePath(basePath, `/setup/users/${encodeURIComponent(user.id)}${tokenQuery}`)}>
                  <strong>{user.username || user.id}</strong>
                  <span>{label}</span>
                </a>
              );
            })}
          </div>
        </aside>
        <section className="panel">
          <h2>{isNew ? 'Add user' : 'User detail'}</h2>
          {notice ? <div className="message">{notice}</div> : null}
          {error ? <div className="message error">{error}</div> : null}
          <form method="post" action={formAction}>
            <div className="form-grid">
              <div className="field"><label>Username</label><input name="username" required defaultValue={values.username} /></div>
              <div className="field"><label>Email</label><input name="email" type="email" defaultValue={values.email} /></div>
              <div className="field">
                <label>Auth provider</label>
                <select name="auth_provider" defaultValue={values.auth_provider}>
                  <option value="local">local</option>
                  <option value="google">google</option>
                </select>
              </div>
              <div className="field">
                <label>TOTP enabled</label>
                <select name="totp_enabled" defaultValue={values.totp_enabled}>
                  <option value="0">No</option>
                  <option value="1">Yes</option>
                </select>
              </div>
              <div className="field full"><label>Password {isNew ? '(required, min 12 chars for local users)' : '(leave empty to keep current)'}</label><input name="password" type="password" /></div>
              <div className="field full"><label>Google subject</label><input name="google_subject" defaultValue={values.google_subject} /></div>
              <div className="field full"><label>Picture URL</label><input name="picture" defaultValue={values.picture} /></div>
            </div>
            <div className="actions">
              <button type="submit">{isNew ? 'Create user' : 'Save changes'}</button>
              {!isNew ? <a className="button-link secondary" href={resolvePath(basePath, `/setup/users/new${tokenQuery}`)}>New user</a> : null}
            </div>
          </form>
          {current ? (
            <form method="post" action={resolvePath(basePath, `/setup/users/${encodeURIComponent(current.id)}/delete${tokenQuery}`)} onSubmit={(event) => {
              if (!window.confirm(`Delete user ${current.username || current.id}?`)) event.preventDefault();
            }}>
              <button className="secondary danger" type="submit">Delete user</button>
            </form>
          ) : null}
          {current ? (
            <div className="meta">
              <div><strong>ID:</strong> {current.id || ''}</div>
              <div><strong>Created:</strong> {current.created_at || ''}</div>
              <div><strong>Updated:</strong> {current.updated_at || ''}</div>
            </div>
          ) : null}
        </section>
      </section>
    </main>
  );
}
