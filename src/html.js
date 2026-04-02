export function escapeHtml(value = '') {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

function renderPage({ title = 'OAuth UI', view = 'login', payload = {} } = {}) {
  const basePath = String(payload?.basePath || '').replace(/\/+$/g, '');
  const uiScriptPath = `${basePath}/app/assets/oidc-ui.js`.replace(/^\/\//, '/');
  const safePayload = JSON.stringify({ view, payload }).replace(/</g, '\\u003c');
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${escapeHtml(title)}</title>
  <script>window.__OIDC_UI__ = ${safePayload};</script>
</head>
<body>
  <div id="oidc-ui-root"></div>
  <script type="module" src="${uiScriptPath}"></script>
</body>
</html>`;
}

export function renderLogin(props = {}) {
  return renderPage({ title: 'Sign in', view: 'login', payload: props });
}

export function renderRegister(props = {}) {
  return renderPage({ title: 'Create account', view: 'register', payload: props });
}

export function renderPasskeyOnboarding(props = {}) {
  return renderPage({ title: 'Complete registration', view: 'passkey_onboarding', payload: props });
}

export function renderConsent(props = {}) {
  return renderPage({ title: 'Authorize application', view: 'consent', payload: props });
}

export function renderExpiredSession(props = {}) {
  return renderPage({ title: 'Session expired', view: 'expired_session', payload: props });
}

export function renderLogout(props = {}) {
  return renderPage({ title: 'Sign out', view: 'logout', payload: props });
}

export function renderLogoutSuccess(props = {}) {
  return renderPage({ title: 'Signed out', view: 'logout_success', payload: props });
}

export function renderLogoutAutoSubmit(props = {}) {
  return renderPage({ title: 'Signing out', view: 'logout_autosubmit', payload: props });
}

export function renderTotpQrSetup(props = {}) {
  return renderPage({ title: 'TOTP setup QR', view: 'totp_qr_setup', payload: props });
}

export function renderUsersAdmin(props = {}) {
  return renderPage({ title: 'User management', view: 'users_admin', payload: props });
}

export function renderOidcSessionsAdmin(props = {}) {
  return renderPage({ title: 'OIDC sessions', view: 'oidc_sessions_admin', payload: props });
}

export function renderRedirectConfigAdmin(props = {}) {
  return renderPage({ title: 'OIDC redirect configuration', view: 'redirect_config_admin', payload: props });
}

export function renderProviderError(props = {}) {
  return renderPage({ title: 'OAuth error', view: 'provider_error', payload: props });
}
