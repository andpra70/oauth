const limits = Object.freeze({ firstName: 100, lastName: 100, note: 2000 });

function clean(value, maxLength) {
  if (typeof value !== 'string') return '';
  return value.trim().slice(0, maxLength);
}

function fallbackNames(user) {
  const parts = String(user.name || '').trim().split(/\s+/).filter(Boolean);
  return {
    firstName: parts.shift() || '',
    lastName: parts.join(' '),
  };
}

export function serializeProfile(user) {
  const fallback = fallbackNames(user);
  return {
    sub: user.googleSub,
    email: user.email,
    firstName: user.firstName || fallback.firstName,
    lastName: user.lastName || fallback.lastName,
    picture: user.picture || '',
    note: user.note || '',
  };
}

export function parseProfileUpdate(body) {
  const input = body && typeof body === 'object' ? body : {};
  return {
    firstName: clean(input.firstName, limits.firstName),
    lastName: clean(input.lastName, limits.lastName),
    note: clean(input.note, limits.note),
  };
}
