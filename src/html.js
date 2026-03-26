export function escapeHtml(value = '') {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

function resolvePath(basePath, path) {
  const normalizedBase = basePath === '/' ? '' : String(basePath || '').replace(/\/+$/g, '');
  const normalizedPath = String(path || '/').startsWith('/') ? String(path || '/') : `/${String(path || '/')}`;
  return normalizedBase ? `${normalizedBase}${normalizedPath}` : normalizedPath;
}

function renderQrSection(qrSetupUrl) {
  if (!qrSetupUrl) return '';

  return `
    <p class="hint"><a href="${escapeHtml(qrSetupUrl)}" target="_blank" rel="noopener noreferrer">Open TOTP setup QR</a></p>
  `;
}

function page(title, body) {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${escapeHtml(title)}</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 460px; margin: 40px auto; padding: 0 16px; background:#0f172a; color:#e2e8f0; }
    .box { border:1px solid #334155; border-radius:12px; padding:20px; background:#111827; }
    label { display:block; margin-top:12px; font-size:14px; }
    input { width:100%; margin-top:6px; padding:10px; border-radius:8px; border:1px solid #475569; background:#0b1220; color:#e2e8f0; }
    button, .button-link { margin-top:16px; width:100%; padding:10px; border:0; border-radius:8px; background:#2563eb; color:white; font-weight:600; cursor:pointer; box-sizing:border-box; text-align:center; display:block; text-decoration:none; }
    .error { color:#fca5a5; margin-top:12px; font-size:14px; }
    .hint { color:#94a3b8; font-size:13px; margin-top:8px; }
    a { color:#93c5fd; }
    .actions { display:grid; gap:8px; margin-top:16px; }
    .separator { margin:20px 0 8px; color:#94a3b8; font-size:13px; text-align:center; }
    .secondary { background:#374151; }
    .auth-grid { display:grid; grid-template-columns: 1fr; gap:16px; align-items:start; }
    .qr-panel { border:1px solid #334155; border-radius:12px; padding:12px; background:#0b1220; }
    @media (min-width: 860px) {
      .box { max-width: 920px; margin: 0 auto; }
      .auth-grid.has-qr { grid-template-columns: minmax(0, 1fr) 280px; }
    }
  </style>
</head>
<body>
  <div class="box">${body}</div>
</body>
</html>`;
}

export function renderLogin({
  basePath = '',
  uid,
  twoFactorEnabled = true,
  error = '',
  username = '',
  otp = '',
  qrSetupUrl = '',
  googleLoginUrl = '',
  googleRegisterUrl = '',
  googleChallenge = '',
  googleAccountLabel = '',
}) {
  const isGoogleTotp = Boolean(googleChallenge);
  const showOtpField = twoFactorEnabled;
  const loginHint = showOtpField
    ? 'Use your username, password and Authenticator code in one step. Google login registers or updates the user and then returns here for TOTP verification.'
    : 'Use your username and password to sign in. Google login registers or updates the user and completes the session without TOTP.';

  return page('Sign in', `
    <h2>Sign in</h2>
    <p class="hint">${escapeHtml(loginHint)}</p>
    <div class="auth-grid">
      <form method="post" action="${escapeHtml(resolvePath(basePath, `/interaction/${uid}/login`))}">
        ${isGoogleTotp ? `<input type="hidden" name="challenge" value="${escapeHtml(googleChallenge)}" />` : ''}
        ${isGoogleTotp
          ? `<p class="hint">Google account: <strong>${escapeHtml(googleAccountLabel || username)}</strong></p>`
          : `
        <label>Username
          <input name="username" autocomplete="username" required value="${escapeHtml(username)}" />
        </label>
        <label>Password
          <input name="password" type="password" autocomplete="current-password" required />
        </label>`}
        ${showOtpField ? `<label>Authenticator code
          <input name="otp" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" placeholder="123456" ${isGoogleTotp ? 'required' : ''} value="${escapeHtml(otp)}" />
        </label>` : ''}
        <button type="submit">${isGoogleTotp ? 'Verify and sign in' : 'Continue'}</button>
        ${renderQrSection(qrSetupUrl)}
      </form>
    </div>
    ${!isGoogleTotp && (googleLoginUrl || googleRegisterUrl) ? '<p class="separator">Google OAuth</p>' : ''}
    ${!isGoogleTotp ? `<div class="actions">
      ${googleLoginUrl ? `<a class="button-link secondary" href="${escapeHtml(googleLoginUrl)}">Accedi con Google</a>` : ''}
      ${googleRegisterUrl ? `<a class="button-link secondary" href="${escapeHtml(googleRegisterUrl)}">Registrati con Google</a>` : ''}
    </div>` : ''}
    ${error ? `<p class="error">${escapeHtml(error)}</p>` : ''}
  `);
}

export function renderConsent({ basePath = '', uid, clientName, scope }) {
  return page('Authorize application', `
    <h2>Authorize application</h2>
    <p><strong>${escapeHtml(clientName)}</strong> requests access.</p>
    <p class="hint">Requested scope: ${escapeHtml(scope || 'openid')}</p>
    <div class="actions">
      <form method="post" action="${escapeHtml(resolvePath(basePath, `/interaction/${uid}/confirm`))}">
        <button type="submit">Allow</button>
      </form>
      <form method="post" action="${escapeHtml(resolvePath(basePath, `/interaction/${uid}/abort`))}">
        <button class="secondary" type="submit">Deny</button>
      </form>
    </div>
  `);
}

export function renderExpiredSession({ basePath = '' } = {}) {
  return page('Session expired', `
    <h2>Session expired</h2>
    <p class="hint">The interaction is no longer valid. Start a new OAuth login flow.</p>
    <div class="actions">
      <form method="get" action="${escapeHtml(resolvePath(basePath, '/app'))}">
        <button type="submit">Open OAuth Console</button>
      </form>
      <form method="get" action="${escapeHtml(resolvePath(basePath, '/'))}">
        <button class="secondary" type="submit">Go to home</button>
      </form>
    </div>
  `);
}

export function renderLogout({ basePath = '', host = '', form = '' } = {}) {
  return page('Sign out', `
    <h2>Sign out</h2>
    <p class="hint">You are about to close the current authorization session for <strong>${escapeHtml(host || 'this provider')}</strong>.</p>
    <div class="actions">
      ${form}
      <button autofocus type="submit" form="op.logoutForm" value="yes" name="logout">Yes, sign me out</button>
      <button class="secondary" type="submit" form="op.logoutForm">No, stay signed in</button>
    </div>
  `);
}

export function renderLogoutSuccess({ basePath = '', clientName = '' } = {}) {
  return page('Signed out', `
    <h2>Signed out</h2>
    <p class="hint">Your session ${clientName ? `for <strong>${escapeHtml(clientName)}</strong> ` : ''}has been closed successfully.</p>
    <div class="actions">
      <form method="get" action="${escapeHtml(resolvePath(basePath, '/app'))}">
        <button type="submit">Open OAuth Console</button>
      </form>
      <form method="get" action="${escapeHtml(resolvePath(basePath, '/example3'))}">
        <button class="secondary" type="submit">Open React Example</button>
      </form>
    </div>
  `);
}

export function renderLogoutAutoSubmit({ form = '' } = {}) {
  return page('Signing out', `
    <h2>Signing out</h2>
    <p class="hint">Your session is being closed automatically.</p>
    ${form}
    <div class="actions">
      <button autofocus type="submit" form="op.logoutForm" value="yes" name="logout">Continue</button>
    </div>
    <script>
      const form = document.getElementById('op.logoutForm');
      if (form) {
        const input = document.createElement('input');
        input.type = 'hidden';
        input.name = 'logout';
        input.value = 'yes';
        form.appendChild(input);
        form.submit();
      }
    </script>
  `);
}

export function renderTotpQrSetup({ username = '', otpauthUrl = '', dataUrl = '' } = {}) {
  return page('TOTP setup QR', `
    <h2>TOTP setup QR</h2>
    <p class="hint">Scan this QR code with your authenticator app${username ? ` for <strong>${escapeHtml(username)}</strong>` : ''}.</p>
    <div class="qr-panel">
      <img src="${escapeHtml(dataUrl)}" alt="TOTP setup QR" style="width:100%; max-width:280px; display:block; margin:0 auto 12px; border-radius:12px; background:white; padding:12px;" />
      <p class="hint">If you cannot scan the QR code, use the OTPAuth URL below.</p>
      <pre style="margin:0; padding:12px; border-radius:12px; background:#111827; color:#e2e8f0; white-space:pre-wrap; word-break:break-word;">${escapeHtml(otpauthUrl)}</pre>
    </div>
  `);
}

export function renderUsersAdmin({
  basePath = '',
  setupToken = '',
  users = [],
  selectedUser = null,
  formValues = {},
  error = '',
  notice = '',
  isNew = false,
} = {}) {
  const tokenQuery = `?token=${encodeURIComponent(setupToken)}`;
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

  const listItems = users.map((user) => {
    const isActive = current?.id === user.id && !isNew;
    const label = user.email || user.username || user.id;
    return `
      <a class="user-link${isActive ? ' active' : ''}" href="${escapeHtml(resolvePath(basePath, `/setup/users/${encodeURIComponent(user.id)}${tokenQuery}`))}">
        <strong>${escapeHtml(user.username || user.id)}</strong>
        <span>${escapeHtml(label)}</span>
      </a>
    `;
  }).join('');

  const deleteForm = current ? `
    <form method="post" action="${escapeHtml(resolvePath(basePath, `/setup/users/${encodeURIComponent(current.id)}/delete${tokenQuery}`))}" onsubmit="return confirm('Delete user ${escapeHtml(current.username || current.id)}?')">
      <button class="secondary danger" type="submit">Delete user</button>
    </form>
  ` : '';

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>User management</title>
  <style>
    body { margin:0; font-family:system-ui,sans-serif; background:#0f172a; color:#e2e8f0; }
    main { width:min(1180px, calc(100% - 32px)); margin:24px auto; display:grid; gap:16px; }
    .shell { display:grid; grid-template-columns: 320px minmax(0, 1fr); gap:16px; align-items:start; }
    .panel { border:1px solid #334155; background:#111827; padding:18px; }
    h1,h2,h3,p { margin:0; }
    .topbar { display:flex; justify-content:space-between; gap:12px; align-items:center; }
    .muted { color:#94a3b8; }
    .list { display:grid; gap:8px; margin-top:16px; }
    .user-link { display:grid; gap:2px; padding:10px 12px; text-decoration:none; color:#e2e8f0; border:1px solid #334155; background:#0b1220; }
    .user-link.active { border-color:#60a5fa; background:#172033; }
    .actions { display:flex; flex-wrap:wrap; gap:8px; margin-top:16px; }
    .form-grid { display:grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap:12px; margin-top:16px; }
    .field { display:grid; gap:6px; }
    .field.full { grid-column:1 / -1; }
    label { font-size:13px; color:#94a3b8; }
    input, select { width:100%; padding:10px; border:1px solid #475569; background:#0b1220; color:#e2e8f0; box-sizing:border-box; }
    button, .button-link { padding:10px 12px; border:0; background:#2563eb; color:#fff; text-decoration:none; cursor:pointer; font-weight:600; display:inline-block; }
    .secondary { background:#374151; }
    .danger { background:#991b1b; }
    .message { margin-top:12px; padding:10px 12px; border:1px solid #334155; background:#0b1220; }
    .message.error { border-color:#7f1d1d; color:#fecaca; }
    .meta { display:grid; gap:6px; margin-top:16px; color:#94a3b8; font-size:13px; }
    @media (max-width: 860px) {
      .shell { grid-template-columns: 1fr; }
      .form-grid { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <main>
    <section class="panel topbar">
      <div>
        <h1>User management</h1>
        <p class="muted">Create, inspect, edit and delete users stored in the JSON database.</p>
      </div>
      <div class="actions">
        <a class="button-link secondary" href="${escapeHtml(resolvePath(basePath, `/setup/users/new${tokenQuery}`))}">Add user</a>
        <a class="button-link secondary" href="${escapeHtml(resolvePath(basePath, `/app`))}">Back to app</a>
      </div>
    </section>

    <section class="shell">
      <aside class="panel">
        <h2>Users</h2>
        <p class="muted" style="margin-top:6px;">${users.length} total</p>
        <div class="list">${listItems || '<p class="muted" style="margin-top:12px;">No users found.</p>'}</div>
      </aside>

      <section class="panel">
        <h2>${isNew ? 'Add user' : 'User detail'}</h2>
        ${notice ? `<div class="message">${escapeHtml(notice)}</div>` : ''}
        ${error ? `<div class="message error">${escapeHtml(error)}</div>` : ''}
        <form method="post" action="${escapeHtml(formAction)}">
          <div class="form-grid">
            <div class="field">
              <label>Username</label>
              <input name="username" required value="${escapeHtml(values.username)}" />
            </div>
            <div class="field">
              <label>Email</label>
              <input name="email" type="email" value="${escapeHtml(values.email)}" />
            </div>
            <div class="field">
              <label>Auth provider</label>
              <select name="auth_provider">
                <option value="local"${values.auth_provider === 'local' ? ' selected' : ''}>local</option>
                <option value="google"${values.auth_provider === 'google' ? ' selected' : ''}>google</option>
              </select>
            </div>
            <div class="field">
              <label>TOTP enabled</label>
              <select name="totp_enabled">
                <option value="0"${values.totp_enabled === '0' ? ' selected' : ''}>No</option>
                <option value="1"${values.totp_enabled === '1' ? ' selected' : ''}>Yes</option>
              </select>
            </div>
            <div class="field full">
              <label>Password ${isNew ? '(required, min 12 chars for local users)' : '(leave empty to keep current)'}</label>
              <input name="password" type="password" ${isNew ? '' : ''} />
            </div>
            <div class="field full">
              <label>Google subject</label>
              <input name="google_subject" value="${escapeHtml(values.google_subject)}" />
            </div>
            <div class="field full">
              <label>Picture URL</label>
              <input name="picture" value="${escapeHtml(values.picture)}" />
            </div>
          </div>
          <div class="actions">
            <button type="submit">${isNew ? 'Create user' : 'Save changes'}</button>
            ${!isNew ? `<a class="button-link secondary" href="${escapeHtml(resolvePath(basePath, `/setup/users/new${tokenQuery}`))}">New user</a>` : ''}
          </div>
        </form>
        ${deleteForm}
        ${current ? `
          <div class="meta">
            <div><strong>ID:</strong> ${escapeHtml(current.id || '')}</div>
            <div><strong>Created:</strong> ${escapeHtml(current.created_at || '')}</div>
            <div><strong>Updated:</strong> ${escapeHtml(current.updated_at || '')}</div>
          </div>
        ` : ''}
      </section>
    </section>
  </main>
</body>
</html>`;
}
