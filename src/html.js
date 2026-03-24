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
    <div class="qr-panel">
      <p class="hint">TOTP setup QR</p>
      <iframe class="qr-frame" src="${escapeHtml(qrSetupUrl)}" title="TOTP QR setup"></iframe>
    </div>
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
    .qr-frame { width:100%; min-height:320px; border:1px solid #334155; border-radius:12px; background:white; margin-top:8px; }
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
  const hasQr = Boolean(qrSetupUrl);

  return page('Sign in', `
    <h2>Sign in</h2>
    <p class="hint">Use your username, password and Authenticator code in one step. Google login registers or updates the user and then returns here for TOTP verification.</p>
    <div class="auth-grid ${hasQr ? 'has-qr' : ''}">
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
        <label>Authenticator code
          <input name="otp" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" placeholder="123456" ${isGoogleTotp ? 'required' : ''} value="${escapeHtml(otp)}" />
        </label>
        <button type="submit">${isGoogleTotp ? 'Verify and sign in' : 'Continue'}</button>
      </form>
      ${renderQrSection(qrSetupUrl)}
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
