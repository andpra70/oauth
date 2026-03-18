export function escapeHtml(value = '') {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
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
    button { margin-top:16px; width:100%; padding:10px; border:0; border-radius:8px; background:#2563eb; color:white; font-weight:600; cursor:pointer; }
    .error { color:#fca5a5; margin-top:12px; font-size:14px; }
    .hint { color:#94a3b8; font-size:13px; margin-top:8px; }
    a { color:#93c5fd; }
    .actions { display:grid; gap:8px; margin-top:16px; }
    .secondary { background:#374151; }
  </style>
</head>
<body>
  <div class="box">${body}</div>
</body>
</html>`;
}

export function renderLogin({ uid, error = '', username = '' }) {
  return page('Sign in', `
    <h2>Sign in</h2>
    <p class="hint">Use your username, password and Authenticator code.</p>
    <form method="post" action="/interaction/${escapeHtml(uid)}/login">
      <label>Username
        <input name="username" autocomplete="username" required value="${escapeHtml(username)}" />
      </label>
      <label>Password
        <input name="password" type="password" autocomplete="current-password" required />
      </label>
      <button type="submit">Continue</button>
    </form>
    ${error ? `<p class="error">${escapeHtml(error)}</p>` : ''}
  `);
}

export function renderTotp({ uid, challenge, error = '', qrSetupUrl = '' }) {
  return page('Two-factor authentication', `
    <h2>Two-factor verification</h2>
    <p class="hint">Enter the 6-digit code from your Authenticator app.</p>
    ${qrSetupUrl ? `<p class="hint"><a href="${escapeHtml(qrSetupUrl)}" target="_blank" rel="noreferrer">Open QR setup</a> for Authenticator.</p>` : ''}
    <form method="post" action="/interaction/${escapeHtml(uid)}/2fa">
      <input type="hidden" name="challenge" value="${escapeHtml(challenge)}" />
      <label>Authenticator code
        <input name="otp" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" required />
      </label>
      <button type="submit">Sign in</button>
    </form>
    ${error ? `<p class="error">${escapeHtml(error)}</p>` : ''}
  `);
}

export function renderConsent({ uid, clientName, scope }) {
  return page('Authorize application', `
    <h2>Authorize application</h2>
    <p><strong>${escapeHtml(clientName)}</strong> requests access.</p>
    <p class="hint">Requested scope: ${escapeHtml(scope || 'openid')}</p>
    <div class="actions">
      <form method="post" action="/interaction/${escapeHtml(uid)}/confirm">
        <button type="submit">Allow</button>
      </form>
      <form method="post" action="/interaction/${escapeHtml(uid)}/abort">
        <button class="secondary" type="submit">Deny</button>
      </form>
    </div>
  `);
}
