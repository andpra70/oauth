function normalizeBase(value) {
  const base = String(value || '/auth').replace(/\/+$/, '');
  return base || '/auth';
}

async function responseJson(response) {
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.error || `HTTP ${response.status}`);
  return body;
}

export function createProfileApi(baseUrl, getAccessToken) {
  const endpoint = `${normalizeBase(baseUrl)}/me`;
  const request = async (options = {}) => {
    const token = await getAccessToken();
    return responseJson(await fetch(endpoint, {
      ...options,
      credentials: 'include',
      headers: {
        ...(options.body ? { 'content-type': 'application/json' } : {}),
        Authorization: `Bearer ${token}`,
      },
    }));
  };
  return {
    get: () => request(),
    update: (profile) => request({ method: 'PUT', body: JSON.stringify(profile) }),
  };
}
