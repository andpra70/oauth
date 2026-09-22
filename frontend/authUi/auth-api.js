export async function authRequest(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    credentials: 'include',
    headers: { ...(options.body ? { 'content-type': 'application/json' } : {}), ...(options.headers || {}) },
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw Object.assign(new Error(payload.message || payload.error || `HTTP ${response.status}`), { payload });
  return payload;
}

const interactionApi = (basePath, uid, suffix = '') => `${basePath}/interaction/${encodeURIComponent(uid)}/api${suffix}`;
export const getInteraction = (basePath, uid) => authRequest(interactionApi(basePath, uid));
export const login = (basePath, uid, body) => authRequest(interactionApi(basePath, uid, '/login'), { method: 'POST', body: JSON.stringify(body) });
export const register = (basePath, uid, body) => authRequest(interactionApi(basePath, uid, '/register'), { method: 'POST', body: JSON.stringify(body) });
export const consent = (basePath, uid, decision) => authRequest(interactionApi(basePath, uid, '/consent'), { method: 'POST', body: JSON.stringify({ decision }) });
export const completeGoogle = (basePath, uid, token) => authRequest(interactionApi(basePath, uid, '/google/complete'), { method: 'POST', body: JSON.stringify({ token }) });
export const passkeyOptions = (basePath, uid, username) => authRequest(`${basePath}/interaction/${encodeURIComponent(uid)}/passkey/options`, { method: 'POST', body: JSON.stringify({ username }) });
export const verifyPasskey = (basePath, uid, body) => authRequest(`${basePath}/interaction/${encodeURIComponent(uid)}/passkey/verify`, { method: 'POST', body: JSON.stringify(body) });
export const completePasskey = (basePath, uid, token) => authRequest(interactionApi(basePath, uid, '/passkey/complete'), { method: 'POST', body: JSON.stringify({ token }) });
