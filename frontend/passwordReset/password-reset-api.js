async function request(basePath, path, body) {
  const response = await fetch(`${basePath}/password-reset/${path}`, { method: 'POST', credentials: 'include', cache: 'no-store', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.error || `HTTP ${response.status}`);
  return payload;
}
export const validateResetToken = (basePath, token) => request(basePath, 'validate', { token });
export const confirmPasswordReset = (basePath, body) => request(basePath, 'confirm', body);
