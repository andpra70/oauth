function normalizeBase(value) {
  return String(value || window.location.origin).replace(/\/+$/, '');
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
    update: (profile) => request({ method: 'PATCH', body: JSON.stringify(profile) }),
  };
}

export async function getAuthFeatures(baseUrl) {
  return responseJson(await fetch(`${normalizeBase(baseUrl)}/config`, {
    credentials: 'include',
    cache: 'no-store',
  }));
}

export async function requestPasswordReset(baseUrl, email) {
  return responseJson(await fetch(`${normalizeBase(baseUrl)}/password-reset/request`, {
    method: 'POST', credentials: 'include', cache: 'no-store', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ email }),
  }));
}
