import { findUserById } from './db.js';

export async function findAccount(_ctx, id) {
  const user = findUserById(id);
  if (!user) return undefined;

  return {
    accountId: user.id,
    async claims(_use, scope) {
      const claims = { sub: user.id };
      if (scope.includes('profile')) {
        claims.preferred_username = user.username;
        if (user.picture) claims.picture = user.picture;
        claims.given_name = user.first_name || '';
        claims.family_name = user.last_name || '';
        claims.name = [user.first_name, user.last_name].filter(Boolean).join(' ') || user.username;
        if (user.role) claims.roles = [user.role];
        if (user.note) claims.note = user.note;
      }
      if (scope.includes('email') && user.email) claims.email = user.email;
      return claims;
    },
  };
}
