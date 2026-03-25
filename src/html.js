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
