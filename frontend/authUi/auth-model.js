export function readAuthUiConfig() {
  const root = document.getElementById('auth-ui-root');
  const query = new URLSearchParams(window.location.search);
  const basePath = String(root?.dataset.basePath || window.__APP_CONFIG__?.basePath || '').replace(/\/+$/, '');
  const pathMatch = window.location.pathname.match(/\/interaction\/([^/]+)\/?$/);
  return { basePath, uid: query.get('uid') || (pathMatch ? decodeURIComponent(pathMatch[1]) : ''), googleToken: query.get('google_token') || '', initialError: query.get('error') || '' };
}

export function follow(result) {
  if (!result?.continueUrl && !result?.redirectTo) return false;
  window.location.assign(result.continueUrl || result.redirectTo);
  return true;
}
