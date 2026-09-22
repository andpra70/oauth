export function createAdminApi(basePath, token) {
  async function request(path, options = {}) {
    const response = await fetch(`${basePath}/setup/api${path}`, { ...options, cache: 'no-store', headers: { 'x-setup-token': token, ...(options.body ? { 'content-type': 'application/json' } : {}), ...(options.headers || {}) } });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(body.error || `HTTP ${response.status}`);
    return body;
  }
  return {
    users: () => request('/users'), createUser: (body) => request('/users', { method: 'POST', body: JSON.stringify(body) }), updateUser: (id, body) => request(`/users/${encodeURIComponent(id)}`, { method: 'PATCH', body: JSON.stringify(body) }), deleteUser: (id) => request(`/users/${encodeURIComponent(id)}`, { method: 'DELETE' }),
    clients: () => request('/clients'), createClient: (body) => request('/clients', { method: 'POST', body: JSON.stringify(body) }), updateClient: (id, body) => request(`/clients/${encodeURIComponent(id)}`, { method: 'PATCH', body: JSON.stringify(body) }), deleteClient: (id) => request(`/clients/${encodeURIComponent(id)}`, { method: 'DELETE' }),
    sessions: () => request('/sessions'), revokeSession: (id) => request(`/sessions/${encodeURIComponent(id)}`, { method: 'DELETE' }), revokeGrant: (id) => request(`/grants/${encodeURIComponent(id)}`, { method: 'DELETE' }), revokeClientToken: (id) => request(`/client-credentials/${encodeURIComponent(id)}`, { method: 'DELETE' }),
    config: () => request('/runtime-config'), updateConfig: (body) => request('/runtime-config', { method: 'PATCH', body: JSON.stringify(body) }),
  };
}
