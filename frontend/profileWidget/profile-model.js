export const EMPTY_PROFILE = Object.freeze({
  email: '', firstName: '', lastName: '', picture: '', note: '',
});

export const DEFAULT_AUTH_FEATURES = Object.freeze({ passkeyEnabled: false, googleEnabled: false, passwordResetEnabled: false });

export function normalizeAuthFeatures(value) {
  return {
    passkeyEnabled: value?.passkeyEnabled === true,
    googleEnabled: value?.googleEnabled === true,
    passwordResetEnabled: value?.passwordResetEnabled === true,
  };
}

export function normalizeProfile(value) {
  const profile = value && typeof value === 'object' ? value : {};
  const nameParts = String(profile.name || profile.preferred_username || '').trim().split(/\s+/).filter(Boolean);
  return {
    email: String(profile.email || ''),
    firstName: String(profile.firstName || profile.given_name || nameParts.shift() || ''),
    lastName: String(profile.lastName || profile.family_name || nameParts.join(' ') || ''),
    picture: String(profile.picture || profile.avatar_url || ''),
    note: String(profile.note || ''),
  };
}

export function editableProfile(profile) {
  return {
    firstName: profile.firstName,
    lastName: profile.lastName,
    note: profile.note,
  };
}
