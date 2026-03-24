const appConfig = window.__APP_CONFIG__ || {};
const baseUrl = new URL(appConfig.baseHref || document.baseURI, window.location.origin);

export function getAppConfig() {
  return appConfig;
}

export function getBaseUrl() {
  return baseUrl;
}

export function appUrl(path = '') {
  return new URL(String(path).replace(/^\/+/, ''), baseUrl).toString();
}

export function appPath(path = '') {
  return new URL(String(path).replace(/^\/+/, ''), baseUrl).pathname;
}

export function resolveBrowserUrl(value) {
  const raw = String(value || '').trim();
  if (!raw) return '';
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(raw)) return raw;
  if (raw.startsWith('/')) return new URL(raw, window.location.origin).toString();
  return new URL(raw, baseUrl).toString();
}

export function issuerEndpoint(issuer, path) {
  return new URL(String(path).replace(/^\/+/, ''), `${String(issuer || '').replace(/\/+$/, '')}/`).toString();
}

export function defaultIssuer() {
  return appConfig.issuer || new URL('.', baseUrl).toString().replace(/\/$/, '');
}
