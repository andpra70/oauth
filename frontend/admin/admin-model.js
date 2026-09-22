export const EMPTY_USER = Object.freeze({ username: '', email: '', password: '', auth_provider: 'local', role: 'user', status: 'active', totp_enabled: '0', first_name: '', last_name: '' });
export const EMPTY_CLIENT = Object.freeze({ client_id: '', client_kind: 'browser', token_endpoint_auth_method: 'none', client_secret: '', scope: 'openid profile email offline_access', grant_types: 'authorization_code\nrefresh_token', response_types: 'code', redirect_uris: '', post_logout_redirect_uris: '' });
export const CONFIG_KEYS = ['twoFactorEnabled', 'consentEnabled', 'googleOAuthEnabled', 'passkeyEnabled', 'confirmLogout'];

export function readAdminConfig() {
  const query = new URLSearchParams(window.location.search);
  const token = query.get('token') || sessionStorage.getItem('oauth.admin.setup-token') || '';
  if (token) sessionStorage.setItem('oauth.admin.setup-token', token);
  if (query.has('token')) window.history.replaceState({}, document.title, window.location.pathname);
  return { basePath: String(window.__APP_CONFIG__?.basePath || '').replace(/\/+$/, ''), token, page: query.get('page') || 'users' };
}

export function userForm(user) {
  return { ...EMPTY_USER, ...(user || {}), password: '', totp_enabled: String(user?.totp_enabled || 0) };
}

export function clientForm(client) {
  const value = { ...EMPTY_CLIENT, ...(client || {}), client_secret: '' };
  for (const key of ['grant_types', 'response_types', 'redirect_uris', 'post_logout_redirect_uris']) value[key] = Array.isArray(value[key]) ? value[key].join('\n') : String(value[key] || '');
  return value;
}

export function clientPayload(form) {
  const result = { ...form };
  for (const key of ['grant_types', 'response_types', 'redirect_uris', 'post_logout_redirect_uris']) result[key] = String(result[key] || '').split(/\r?\n|,/).map((item) => item.trim()).filter(Boolean);
  if (!result.client_secret) delete result.client_secret;
  return result;
}
