export function readResetConfig() {
  const query = new URLSearchParams(window.location.search);
  const token = query.get('token') || sessionStorage.getItem('oauth.password-reset-token') || '';
  if (token) sessionStorage.setItem('oauth.password-reset-token', token);
  if (query.has('token')) window.history.replaceState({}, document.title, window.location.pathname);
  return { basePath: String(window.__APP_CONFIG__?.basePath || '').replace(/\/+$/, ''), token };
}
